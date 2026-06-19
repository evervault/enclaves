#![allow(dead_code)]

use std::convert::Infallible;
use std::future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use hyper::{Body, Request, Response};
use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;
use tower::Service;

use crate::e3client::E3Client;
use crate::server::config::AcceptorConfig;
use crate::server::error::TlsError;
use crate::server::handshake::Handshaker;
use crate::server::metrics::AcceptMetrics;
use crate::server::server::run_with;
use crate::utils::trx_handler::LogHandlerMessage;
use crate::{EnclaveContext, FeatureContext};

#[cfg(feature = "network_egress")]
use shared::server::egress::{EgressConfig, EgressDestinations};

// ---------------------------------------------------------------------------
// Single-knob harness config (§3.1). Layer A drives mostly off `acceptor`; the
// customer / client / runtime knobs are consumed by the Layer-B harness.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum CustomerBehaviour {
    Echo,
    HttpOk,
    Slow(Duration),
    Refuse,
}

#[derive(Clone, Debug)]
pub struct ClientPlan {
    pub count: usize,
    pub concurrency: usize,
    /// Per-client delay before sending the first byte (models a slow client).
    pub stall_before_hello: Option<Duration>,
}

impl Default for ClientPlan {
    fn default() -> Self {
        Self {
            count: 1,
            concurrency: 1,
            stall_before_hello: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RuntimeFlavour {
    CurrentThread,
    MultiThread(usize),
}

pub struct HarnessConfig {
    pub acceptor: AcceptorConfig,
    pub customer: CustomerBehaviour,
    pub client_plan: ClientPlan,
    pub runtime: RuntimeFlavour,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            acceptor: AcceptorConfig::serial_compat(),
            customer: CustomerBehaviour::HttpOk,
            client_plan: ClientPlan::default(),
            runtime: RuntimeFlavour::CurrentThread,
        }
    }
}

// ---------------------------------------------------------------------------
// Fake connections
// ---------------------------------------------------------------------------

/// What a fake handshake should do for a given connection.
#[derive(Clone, Debug)]
pub enum HandshakeBehaviour {
    /// Complete immediately (success).
    Instant,
    /// Complete successfully after sleeping for `Duration` (works with the
    /// paused clock + `tokio::time::advance`).
    SucceedAfter(Duration),
    /// Fail immediately.
    Fail,
    /// Never complete — models a stalled `ClientHello`.
    Stall,
}

/// The *raw* connection handed to the (fake) handshaker. Carries the per-conn
/// id + behaviour; its byte stream is inert (the [`FakeHandshaker`] ignores it).
pub struct ScriptedConn {
    pub id: usize,
    pub behaviour: HandshakeBehaviour,
    pub remote_addr: Option<String>,
    /// How long the *serve* phase should occupy the connection before EOF.
    /// `None` => serve returns immediately (EOF). Used to make connections
    /// linger in-flight (holding a connection permit) after the handshake, so
    /// tests can show in-flight exceeding the handshake cap.
    pub serve_delay: Option<Duration>,
}

impl AsyncRead for ScriptedConn {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Immediate EOF — the raw stream is never read in the policy layer.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The connection produced by a successful fake handshake — what the serve loop
/// reads/writes. Reads (optionally) wait out a serve delay, serve an optional
/// preloaded buffer, then EOF; writes are discarded; the remote addr is
/// configurable (for `ProxiedConnection`).
pub struct FakeServedConn {
    read_data: Vec<u8>,
    read_pos: usize,
    remote_addr: Option<String>,
    /// Pending serve-delay timer; the first read pends until it fires.
    serve_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl FakeServedConn {
    pub fn eof(remote_addr: Option<String>) -> Self {
        Self::eof_after(remote_addr, None)
    }

    /// EOF after `serve_delay` (modelling a serve phase that holds the
    /// connection in-flight). Must be called within a tokio runtime when
    /// `serve_delay` is `Some` (it arms a timer).
    pub fn eof_after(remote_addr: Option<String>, serve_delay: Option<Duration>) -> Self {
        Self {
            read_data: Vec::new(),
            read_pos: 0,
            remote_addr,
            serve_delay: serve_delay.map(|d| Box::pin(tokio::time::sleep(d))),
        }
    }

    pub fn with_request(bytes: Vec<u8>, remote_addr: Option<String>) -> Self {
        Self {
            read_data: bytes,
            read_pos: 0,
            remote_addr,
            serve_delay: None,
        }
    }
}

impl AsyncRead for FakeServedConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(sleep) = this.serve_delay.as_mut() {
            match std::future::Future::poll(sleep.as_mut(), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => this.serve_delay = None,
            }
        }
        if this.read_pos < this.read_data.len() {
            let remaining = &this.read_data[this.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.read_pos += n;
        }
        // Nothing left => Ready with no bytes put == EOF.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FakeServedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl ProxiedConnection for FakeServedConn {
    fn get_remote_addr(&self) -> Option<String> {
        self.remote_addr.clone()
    }
}

// ---------------------------------------------------------------------------
// Scripted listener
// ---------------------------------------------------------------------------

/// In-memory [`Listener`] backed by a channel of pre-built connections. Once
/// the queue drains it *idles* (an empty channel makes `accept()` pend) rather
/// than erroring, mimicking a real listener waiting for the next connection.
pub struct ScriptedListener {
    rx: tokio::sync::mpsc::UnboundedReceiver<ScriptedConn>,
}

#[async_trait]
impl Listener for ScriptedListener {
    type Connection = ScriptedConn;
    type Error = TlsError;

    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        match self.rx.recv().await {
            Some(conn) => Ok(conn),
            // No more scripted connections — idle forever like a quiet listener.
            None => future::pending().await,
        }
    }
}

impl ScriptedListener {
    /// A listener fed dynamically through a [`ScriptedSender`]. While the sender
    /// is alive an empty queue makes `accept()` pend (a quiet listener); drop the
    /// sender to make it idle permanently. Use this to inject a connection *after*
    /// advancing the clock (e.g. to prove a freed handshake slot lets a later conn
    /// through).
    pub fn channel() -> (Self, ScriptedSender) {
        let (tx, rx) = unbounded_channel();
        (
            Self { rx },
            ScriptedSender {
                tx,
                next_id: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
        )
    }
}

/// Handle for injecting connections into a channel-backed [`ScriptedListener`].
#[derive(Clone)]
pub struct ScriptedSender {
    tx: UnboundedSender<ScriptedConn>,
    next_id: Arc<std::sync::atomic::AtomicUsize>,
}

impl ScriptedSender {
    /// Inject a connection; returns its assigned id.
    pub fn send(&self, behaviour: HandshakeBehaviour) -> usize {
        self.send_with_addr(behaviour, None)
    }

    pub fn send_with_addr(
        &self,
        behaviour: HandshakeBehaviour,
        remote_addr: Option<String>,
    ) -> usize {
        self.send_spec(behaviour, remote_addr, None)
    }

    /// Inject a connection with full control over its remote addr and serve
    /// delay.
    pub fn send_spec(
        &self,
        behaviour: HandshakeBehaviour,
        remote_addr: Option<String>,
        serve_delay: Option<Duration>,
    ) -> usize {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = self.tx.send(ScriptedConn {
            id,
            behaviour,
            remote_addr,
            serve_delay,
        });
        id
    }
}

/// Builder that assigns sequential ids and pre-loads a [`ScriptedListener`].
#[derive(Default)]
pub struct ScriptedListenerBuilder {
    conns: Vec<ScriptedConn>,
    next_id: usize,
}

impl ScriptedListenerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, behaviour: HandshakeBehaviour) -> usize {
        self.push_with_addr(behaviour, None)
    }

    pub fn push_with_addr(
        &mut self,
        behaviour: HandshakeBehaviour,
        remote_addr: Option<String>,
    ) -> usize {
        self.push_spec(behaviour, remote_addr, None)
    }

    /// Add a connection with full control over its remote addr and serve delay.
    pub fn push_spec(
        &mut self,
        behaviour: HandshakeBehaviour,
        remote_addr: Option<String>,
        serve_delay: Option<Duration>,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.conns.push(ScriptedConn {
            id,
            behaviour,
            remote_addr,
            serve_delay,
        });
        id
    }

    /// Add `n` connections sharing one behaviour; returns their ids in order.
    pub fn push_many(&mut self, n: usize, behaviour: HandshakeBehaviour) -> Vec<usize> {
        (0..n).map(|_| self.push(behaviour.clone())).collect()
    }

    /// Add `n` connections sharing one behaviour and serve delay.
    pub fn push_many_spec(
        &mut self,
        n: usize,
        behaviour: HandshakeBehaviour,
        serve_delay: Option<Duration>,
    ) -> Vec<usize> {
        (0..n)
            .map(|_| self.push_spec(behaviour.clone(), None, serve_delay))
            .collect()
    }

    /// Pre-load every connection and drop the sender so the listener idles once
    /// drained.
    pub fn build(self) -> ScriptedListener {
        let (tx, rx) = unbounded_channel();
        for conn in self.conns {
            let _ = tx.send(conn);
        }
        // `tx` dropped here → `rx.recv()` yields the queued conns then `None`.
        ScriptedListener { rx }
    }
}

// ---------------------------------------------------------------------------
// Fake handshaker
// ---------------------------------------------------------------------------

/// Handshaker that runs the per-connection [`HandshakeBehaviour`] instead of
/// real TLS, recording completion order so tests can assert interleaving.
#[derive(Clone, Default)]
pub struct FakeHandshaker {
    completion_log: Arc<Mutex<Vec<usize>>>,
}

impl FakeHandshaker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ids of connections whose handshake completed successfully, in the order
    /// they completed.
    pub fn completion_order(&self) -> Vec<usize> {
        self.completion_log.lock().unwrap().clone()
    }
}

fn fake_handshake_error() -> TlsError {
    TlsError::IoError(io::Error::other("fake handshake failure"))
}

#[async_trait]
impl Handshaker<ScriptedConn> for FakeHandshaker {
    type Output = FakeServedConn;

    async fn handshake(&self, raw: ScriptedConn) -> Result<Self::Output, TlsError> {
        match raw.behaviour {
            HandshakeBehaviour::Instant => {}
            HandshakeBehaviour::SucceedAfter(d) => tokio::time::sleep(d).await,
            HandshakeBehaviour::Fail => return Err(fake_handshake_error()),
            HandshakeBehaviour::Stall => {
                // Never resolves; cancelled by a handshake timeout (M3) or task abort.
                future::pending::<()>().await;
            }
        }
        self.completion_log.lock().unwrap().push(raw.id);
        Ok(FakeServedConn::eof_after(raw.remote_addr, raw.serve_delay))
    }
}

// ---------------------------------------------------------------------------
// Driving run_with
// ---------------------------------------------------------------------------

/// Trivial leaf service that always returns 200 OK — used when the serve loop's
/// behaviour is irrelevant to the property under test (policy layer).
#[derive(Clone)]
pub struct OkService;

impl Service<Request<Body>> for OkService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = future::Ready<Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        future::ready(Ok(Response::new(Body::from("OK"))))
    }
}

/// Build a minimal `FeatureContext` for the harness (auth disabled, no egress).
pub fn fake_feature_context() -> FeatureContext {
    FeatureContext {
        api_key_auth: false,
        healthcheck: None,
        healthcheck_port: None,
        healthcheck_use_tls: None,
        trx_logging_enabled: false,
        forward_proxy_protocol: false,
        trusted_headers: Vec::new(),
        attestation_cors: None,
        #[cfg(feature = "network_egress")]
        egress: EgressConfig {
            allow_list: EgressDestinations {
                wildcard: Default::default(),
                exact: Default::default(),
                allow_all: Default::default(),
                ips: Default::default(),
            },
        },
        acceptor: AcceptorConfig::serial_compat(),
    }
}

fn fake_enclave_context() -> EnclaveContext {
    EnclaveContext::new(
        "team_uuid".into(),
        "app_uuid".into(),
        "enclave_uuid".into(),
        "my-enclave".into(),
    )
}

/// Spawn `run_with` driven by the policy-layer fakes. The serve dependencies
/// (a 200-OK service, fake contexts, a drained trx-log channel) are constructed
/// internally. Returns the join handle so the test can `abort()` the (forever)
/// loop once its assertions are done.
pub fn spawn_policy_server(
    listener: ScriptedListener,
    handshaker: FakeHandshaker,
    config: AcceptorConfig,
    metrics: Arc<AcceptMetrics>,
) -> JoinHandle<()> {
    // Keep the trx-log receiver alive + drained so any `tx.send` succeeds.
    let (tx, mut rx): (UnboundedSender<LogHandlerMessage>, _) = unbounded_channel();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let enclave_context = Arc::new(fake_enclave_context());
    let feature_context = Arc::new(fake_feature_context());
    let e3_client = Arc::new(E3Client::new());

    tokio::spawn(async move {
        let _ = run_with(
            listener,
            handshaker,
            config,
            OkService,
            0,
            enclave_context,
            feature_context,
            e3_client,
            tx,
            metrics,
        )
        .await;
    })
}

/// Poll `pred` until it returns true or `timeout` elapses; returns whether it
/// became true. Intended for *non-paused* tests (the self-test, Layer B).
pub async fn wait_until<F: FnMut() -> bool>(mut pred: F, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if pred() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .is_ok()
}

/// Yield repeatedly to let all *currently-runnable* tasks reach a fixed point
/// **without advancing the (paused) clock** — `yield_now` reschedules rather
/// than parking on a timer, so the virtual clock stays put. Use in
/// `start_paused` tests to flush task progress after injecting work or calling
/// `tokio::time::advance`.
pub async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

/// Like [`settle`] but stops early once `pred` holds; returns whether it did.
/// Does not advance the clock, so a predicate that only becomes true after time
/// passes will return `false` (advance the clock first).
pub async fn settle_until<F: FnMut() -> bool>(mut pred: F) -> bool {
    for _ in 0..2000 {
        if pred() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    pred()
}

#[cfg(test)]
mod self_test {
    use super::*;

    // Proves the scaffolding can actually drive `run_with`: three instant
    // connections are accepted, handshaked and served.
    #[tokio::test]
    async fn harness_drives_run_with() {
        let metrics = AcceptMetrics::new();
        let handshaker = FakeHandshaker::new();
        let mut builder = ScriptedListenerBuilder::new();
        builder.push_many(3, HandshakeBehaviour::Instant);
        let listener = builder.build();

        let handle = spawn_policy_server(
            listener,
            handshaker.clone(),
            AcceptorConfig::serial_compat(),
            metrics.clone(),
        );

        assert!(
            wait_until(|| metrics.served() == 3, Duration::from_secs(5)).await,
            "expected all 3 connections to be served, metrics = {metrics:?}"
        );

        assert_eq!(metrics.accepted(), 3);
        assert_eq!(metrics.handshake_ok(), 3);
        assert_eq!(metrics.served(), 3);
        assert_eq!(handshaker.completion_order().len(), 3);

        handle.abort();
    }
}
