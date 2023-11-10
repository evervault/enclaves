use super::error::TlsError;
use super::http::parse::{try_parse_http_request_from_stream, Incoming};
use super::tls::TlsServerBuilder;

#[cfg(feature = "enclave")]
use crate::crypto::attest;
use crate::e3client::E3Client;
use crate::server::layers::decrypt::DecryptLayer;
#[cfg(feature = "enclave")]
use crate::server::tls::TRUSTED_PUB_CERT;
use crate::{CageContext, FEATURE_CONTEXT};

use crate::utils::trx_handler::{start_log_handler, LogHandlerMessage};

use bytes::Bytes;
use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::server::TlsStream;
use tower::Service;

#[cfg(feature = "enclave")]
use super::layers::attest::AttestLayer;
use super::layers::{auth::AuthLayer, forward::ForwardService};

pub async fn run<L: Listener + Send + Sync>(tcp_server: L, port: u16)
where
    TlsError: From<<L as Listener>::Error>,
    <L as Listener>::Connection: ProxiedConnection + 'static,
{
    let mut server = TlsServerBuilder::new()
        .with_server(tcp_server)
        .with_attestable_cert()
        .await
        .expect("Failed to create tls server");
    let e3_client = Arc::new(E3Client::new());

    let (tx, rx): (
        UnboundedSender<LogHandlerMessage>,
        UnboundedReceiver<LogHandlerMessage>,
    ) = unbounded_channel();

    let feature_context = FEATURE_CONTEXT.get().expect("Couldn't get feature context");
    if feature_context.trx_logging_enabled {
        let tx_for_handler = tx.clone();
        tokio::spawn(async move {
            start_log_handler(tx_for_handler, rx).await;
        });
    }

    let http_client = hyper::Client::new();
    log::info!("TLS Server Created - Listening for new connections.");

    let cage_context = match CageContext::get() {
        Ok(context) => context,
        Err(e) => {
            log::error!("Failed to read cage context in data plane server - {e}");
            return;
        }
    };
    let mut service_builder = tower::ServiceBuilder::new();

    // Only apply attestation layer in enclave mode
    #[cfg(feature = "enclave")]
    let mut service_builder = service_builder.layer(AttestLayer);

    // layers are invoked in the order that they're registered to the service
    let mut service = service_builder
        .layer(AuthLayer::new(e3_client.clone(), Arc::new(cage_context)))
        .layer(DecryptLayer::new(e3_client.clone()))
        .service(ForwardService);
    loop {
        let mut stream = match server.accept().await {
            Ok(stream) => stream,
            Err(tls_err) => {
                log::error!(
                    "An error occurred while accepting the incoming connection — {tls_err}"
                );
                continue;
            }
        };

        let e3_client_for_connection = e3_client.clone();
        let tx_for_connection = tx.clone();
        let cloned_http_client = http_client.clone();
        tokio::spawn(async move {
            let e3_client_for_tcp = e3_client_for_connection.clone();
            let tx_for_tcp = tx_for_connection.clone();
            let remote_ip = stream.get_ref().0.get_remote_addr();
            match try_parse_http_request_from_stream(&mut stream, port).await {
                Ok(Incoming::HttpRequest(request)) => {
                    return;
                }
                Ok(Incoming::NonHttpRequest(bytes)) => {
                    return;
                }
                Err(e) => {
                    log::error!("Connection read error - {e:?}");
                    shutdown_conn(&mut stream).await;
                    return;
                }
            };
        });
    }
}

async fn shutdown_conn<L>(stream: &mut TlsStream<L>)
where
    TlsStream<L>: AsyncWriteExt + Unpin,
{
    if let Err(e) = stream.shutdown().await {
        log::error!("Failed to shutdown data plane connection — {e:?}");
    }
}
