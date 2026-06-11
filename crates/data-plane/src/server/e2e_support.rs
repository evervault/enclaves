#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{Certificate, ClientConfig, Error as RustlsError, ServerName};
use tokio_rustls::TlsConnector;

use shared::server::TcpServer;

use crate::e3client::E3Client;
use crate::server::config::AcceptorConfig;
use crate::server::handshake::TlsHandshaker;
use crate::server::layers::context_log::ContextLogLayer;
use crate::server::layers::decrypt::DecryptLayer;
use crate::server::layers::forward::ForwardService;
use crate::server::metrics::AcceptMetrics;
use crate::server::server::run_with;
use crate::server::test_support::fake_feature_context;
use crate::server::tls::test_certs::test_tls_acceptor;
use crate::{EnclaveContext, FeatureContext};

use crate::server::layers::auth::AuthLayer;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

/// Seed the process-global `EnclaveContext`. The set is `get_or_init` (first
/// writer wins, process-wide), so these values **must match** the cert-resolver
/// tests' `init_context` to avoid cross-test contamination — whichever
/// `#[serial]` test runs first fixes the context for the whole binary.
pub fn seed_enclave_context() {
    EnclaveContext::set(EnclaveContext::new(
        "app_123".into(),
        "team_456".into(),
        "enclave_123".into(),
        "my-sick-enclave".into(),
    ));
}

// ---------------------------------------------------------------------------
// TLS client
// ---------------------------------------------------------------------------

/// Client-side verifier that trusts any server cert. Identity in this product
/// comes from attestation, not the TLS PKI; for tests we only care that the
/// real handshake + data path work (mirrors the repo's `OpenServerCertVerifier`).
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn test_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// TCP-connect, optionally write a raw prefix (e.g. a PROXY v2 header) before
/// the TLS `ClientHello`, then complete the TLS handshake.
pub async fn connect_tls_with_prefix(
    addr: SocketAddr,
    raw_prefix: Option<&[u8]>,
) -> ClientTlsStream<TcpStream> {
    let mut tcp = TcpStream::connect(addr).await.expect("tcp connect");
    if let Some(prefix) = raw_prefix {
        tcp.write_all(prefix).await.expect("write raw prefix");
    }
    let connector = test_tls_connector();
    // Any non-nonce, non-trusted DNS name resolves to the base attestable cert.
    let domain = ServerName::try_from("data-plane.local").expect("valid server name");
    connector.connect(domain, tcp).await.expect("tls handshake")
}

pub async fn connect_tls(addr: SocketAddr) -> ClientTlsStream<TcpStream> {
    connect_tls_with_prefix(addr, None).await
}

/// Read from `stream` until EOF or an idle gap (no bytes for `idle`). Used to
/// collect a complete HTTP response over a keep-alive connection (which the
/// server holds open after responding).
pub async fn read_until_idle<S: AsyncReadExt + Unpin>(stream: &mut S, idle: Duration) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(idle, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf
}

/// One-shot: open a TLS connection, send `request`, return the response bytes.
pub async fn request_response(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = connect_tls(addr).await;
    stream.write_all(request).await.expect("write request");
    read_until_idle(&mut stream, Duration::from_millis(300)).await
}

// ---------------------------------------------------------------------------
// Fake customer process
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum CustomerMode {
    /// Echo every byte back (for non-HTTP / websocket pipe tests).
    Echo,
    /// Respond to any request with a fixed `200 OK`.
    HttpOk,
    /// Respond `200 OK` whose body is the raw request received (so the test can
    /// inspect the headers the data plane forwarded, e.g. `X-Forwarded-For`).
    ReflectRequest,
    /// Respond `200 OK` after a delay.
    Slow(Duration),
    /// Nothing listening — connections are refused (customer down).
    Refuse,
}

/// A fake customer process on `127.0.0.1`. The data plane forwards to
/// `127.0.0.1:<port>`, so pass [`Self::port`] as the data-plane port.
pub struct FakeCustomer {
    pub addr: SocketAddr,
    _handle: Option<JoinHandle<()>>,
}

impl FakeCustomer {
    pub async fn spawn(mode: CustomerMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind customer");
        let addr = listener.local_addr().expect("customer addr");

        if let CustomerMode::Refuse = mode {
            // Drop the listener so connections to `addr` are refused.
            drop(listener);
            return Self {
                addr,
                _handle: None,
            };
        }

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    match mode {
                        CustomerMode::Echo => {
                            let (mut r, mut w) = sock.split();
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                        }
                        CustomerMode::HttpOk => respond_ok(&mut sock).await,
                        CustomerMode::ReflectRequest => reflect_request(&mut sock).await,
                        CustomerMode::Slow(delay) => {
                            tokio::time::sleep(delay).await;
                            respond_ok(&mut sock).await;
                        }
                        CustomerMode::Refuse => unreachable!(),
                    }
                });
            }
        });

        Self {
            addr,
            _handle: Some(handle),
        }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

async fn respond_ok(sock: &mut TcpStream) {
    let mut buf = [0u8; 8192];
    // Read (at least) the request head; ignore the contents.
    let _ = sock.read(&mut buf).await;
    let response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nOK";
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
}

async fn reflect_request(sock: &mut TcpStream) {
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await.unwrap_or(0);
    let body = &buf[..n];
    let header = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = sock.write_all(header.as_bytes()).await;
    let _ = sock.write_all(body).await;
    let _ = sock.flush().await;
}

/// A PROXY-protocol v2 header for a TCP/IPv4 connection from `1.2.3.4:80` to
/// `5.6.7.8:443`, to be written on the raw socket before the TLS `ClientHello`.
pub fn proxy_v2_header_ipv4() -> Vec<u8> {
    vec![
        // 12-byte v2 signature
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        0x21, // version 2 | PROXY command
        0x11, // AF_INET | STREAM
        0x00, 0x0C, // 12 bytes of address data follow
        1, 2, 3, 4, // source address 1.2.3.4
        5, 6, 7, 8, // destination address 5.6.7.8
        0x00, 0x50, // source port 80
        0x01, 0xBB, // destination port 443
    ]
}

// ---------------------------------------------------------------------------
// Real TLS server under test
// ---------------------------------------------------------------------------

/// A running data-plane server (real TLS) on loopback. `Drop` aborts the accept
/// loop.
pub struct TestServerHandle {
    pub addr: SocketAddr,
    pub config: AcceptorConfig,
    pub metrics: Arc<AcceptMetrics>,
    handle: JoinHandle<Result<(), crate::server::error::TlsError>>,
}

impl Drop for TestServerHandle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl TestServerHandle {
    /// Spawn `run_with` against a fresh `127.0.0.1:0` TCP listener, terminating
    /// real TLS and forwarding to `customer_port`.
    pub async fn spawn(
        config: AcceptorConfig,
        customer_port: u16,
        feature_context: FeatureContext,
        metrics: Arc<AcceptMetrics>,
    ) -> Self {
        seed_enclave_context();

        let listener = TcpServer::bind("127.0.0.1:0").await.expect("bind server");
        let addr = listener.local_addr().expect("server addr");

        let handshaker = TlsHandshaker::new(test_tls_acceptor());
        let enclave_context = Arc::new(EnclaveContext::get().expect("context seeded"));
        let feature_context = Arc::new(feature_context);
        let e3_client = Arc::new(E3Client::new());

        // Keep the trx-log channel alive + drained.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        // The production tower stack (no AttestLayer — that is enclave-only).
        let service = tower::ServiceBuilder::new()
            .layer(ContextLogLayer::new(
                enclave_context.clone(),
                feature_context.clone(),
                tx.clone(),
            ))
            .option_layer(
                feature_context
                    .api_key_auth
                    .then(|| AuthLayer::new(e3_client.clone(), enclave_context.clone())),
            )
            .layer(DecryptLayer::new(e3_client.clone()))
            .service(ForwardService);

        let handle = tokio::spawn(run_with(
            listener,
            handshaker,
            config.clone(),
            service,
            customer_port,
            enclave_context,
            feature_context,
            e3_client,
            tx,
            metrics.clone(),
        ));

        Self {
            addr,
            config,
            metrics,
            handle,
        }
    }
}

/// Build a feature context with auth toggled (other fields defaulted).
pub fn feature_context_with_auth(api_key_auth: bool) -> FeatureContext {
    FeatureContext {
        api_key_auth,
        ..fake_feature_context()
    }
}

#[cfg(test)]
mod smoke {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn server_starts_and_serves_a_request() {
        let customer = FakeCustomer::spawn(CustomerMode::HttpOk).await;
        let metrics = AcceptMetrics::new();
        let server = TestServerHandle::spawn(
            AcceptorConfig::serial_compat(),
            customer.port(),
            feature_context_with_auth(false),
            metrics,
        )
        .await;

        let response = request_response(server.addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200"), "expected 200 OK, got: {text:?}");
    }
}
