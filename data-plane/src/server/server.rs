use super::error::TlsError;
use super::http::parse::{try_parse_http_request_from_stream, Incoming};
use super::http::{request_to_bytes, response_to_bytes};
use super::tls::TlsServerBuilder;

#[cfg(feature = "enclave")]
use crate::crypto::attest;
use crate::e3client::E3Client;
use crate::server::http::parse;
use crate::server::layers::auth::AuthError;
use crate::server::layers::context_log::ContextLogLayer;
#[cfg(feature = "enclave")]
use crate::server::tls::TRUSTED_PUB_CERT;
use crate::{CageContext, FeatureContext};

use crate::utils::trx_handler::{start_log_handler, LogHandlerMessage};

use hyper::{Body, Request};
use shared::logging::{RequestType, TrxContextBuilder};
use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::server::TlsStream;
use tower::Service;

#[cfg(feature = "enclave")]
use super::layers::attest::AttestLayer;
use super::layers::{
    auth::{auth_request, AuthLayer},
    decrypt::DecryptLayer,
    forward::ForwardService,
};

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

    let feature_context = Arc::new(FeatureContext::get());
    if feature_context.trx_logging_enabled {
        let tx_for_handler = tx.clone();
        tokio::spawn(async move {
            start_log_handler(tx_for_handler, rx).await;
        });
    }

    log::info!("TLS Server Created - Listening for new connections.");
    let cage_context = match CageContext::get() {
        Ok(context) => Arc::new(context),
        Err(e) => {
            log::error!("Failed to read cage context in data plane server - {e}");
            return;
        }
    };
    let service_builder = tower::ServiceBuilder::new();

    // Only apply attestation layer in enclave mode
    #[cfg(feature = "enclave")]
    let service_builder = service_builder.layer(AttestLayer);

    // layers are invoked in the order that they're registered to the service
    let service = service_builder
        .layer(ContextLogLayer::new(
            cage_context.clone(),
            feature_context.clone(),
            tx.clone(),
        ))
        .option_layer(
            feature_context
                .api_key_auth
                .then(|| AuthLayer::new(e3_client.clone(), cage_context.clone())),
        )
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

        let remote_ip = stream.get_remote_addr().clone();
        let tx_for_connection = tx.clone();
        let mut data_plane_service = service.clone();
        let cage_context_clone = cage_context.clone();
        let feature_context_clone = feature_context.clone();
        let e3_client_clone = e3_client.clone();
        tokio::spawn(async move {
            loop {
                match try_parse_http_request_from_stream(&mut stream, port).await {
                    Ok(Incoming::HttpRequest(request)) if parse::is_websocket_request(&request) => {
                        return handle_websocket_request(
                            &mut stream,
                            request,
                            &tx_for_connection,
                            remote_ip,
                            cage_context_clone.clone(),
                            e3_client_clone.clone(),
                            port,
                        )
                        .await;
                    }
                    Ok(Incoming::HttpRequest(request)) => {
                        let response = data_plane_service.call(request).await.unwrap();
                        let response_bytes = response_to_bytes(response).await;
                        let _ = stream.write_all(&response_bytes).await;
                        continue;
                    }
                    Ok(Incoming::NonHttpRequest(_)) if feature_context_clone.api_key_auth => {
                        log::info!(
                            "Non http request received with auth enabled, closing connection"
                        );
                        let _ = log_non_http_trx(&tx_for_connection, false, remote_ip);
                        shutdown_conn(&mut stream).await;
                        return;
                    }
                    Ok(Incoming::NonHttpRequest(bytes)) => {
                        log::info!(
                            "Non http request received with auth enabled, closing connection"
                        );
                        let _ = log_non_http_trx(&tx_for_connection, true, remote_ip);
                        let _ = pipe_to_customer_process(&mut stream, &bytes, port).await;
                        return;
                    }
                    Err(e) => {
                        log::error!("Connection read error - {e:?}");
                        shutdown_conn(&mut stream).await;
                        return;
                    }
                };
            }
        });
    }
}

async fn handle_websocket_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
    request: Request<Body>,
    tx_for_connection: &UnboundedSender<LogHandlerMessage>,
    remote_ip: Option<String>,
    cage_context: Arc<CageContext>,
    e3_client: Arc<E3Client>,
    port: u16,
) {
    let api_key = match request
        .headers()
        .get("api-key")
        .ok_or(AuthError::NoApiKeyGiven)
    {
        Ok(api_key) => api_key,
        Err(e) => {
            let response_bytes = response_to_bytes(e.into()).await;
            let _ = log_non_http_trx(&tx_for_connection, false, remote_ip);
            let _ = stream.write_all(&response_bytes).await;
            return;
        }
    };
    if let Err(auth_err) = auth_request(api_key, cage_context, e3_client).await {
        let response_bytes = response_to_bytes(auth_err.into()).await;
        let _ = log_non_http_trx(&tx_for_connection, false, remote_ip);
        let _ = stream.write_all(&response_bytes).await;
        return;
    }
    let _ = log_non_http_trx(&tx_for_connection, true, remote_ip);
    let serialized_request = request_to_bytes(request).await;
    let _ = pipe_to_customer_process(stream, &serialized_request, port).await;
    return;
}

async fn shutdown_conn<L>(stream: &mut TlsStream<L>)
where
    TlsStream<L>: AsyncWriteExt + Unpin,
{
    if let Err(e) = stream.shutdown().await {
        log::error!("Failed to shutdown data plane connection — {e:?}");
    }
}

async fn pipe_to_customer_process<L>(
    stream: &mut TlsStream<L>,
    buffer: &[u8],
    port: u16,
) -> Result<(), tokio::io::Error>
where
    TlsStream<L>: AsyncRead + Unpin + AsyncWrite,
{
    let mut customer_stream = TcpStream::connect(("127.0.0.1", port)).await?;
    customer_stream.write_all(buffer).await?;
    shared::utils::pipe_streams(stream, customer_stream).await?;
    Ok(())
}

fn log_non_http_trx(
    tx_sender: &UnboundedSender<LogHandlerMessage>,
    authorized: bool,
    remote_ip: Option<String>,
) {
    let cage_context = CageContext::get().unwrap();
    let mut context_builder = TrxContextBuilder::init_trx_context_with_cage_details(
        &cage_context.cage_uuid,
        &cage_context.cage_name,
        &cage_context.app_uuid,
        &cage_context.team_uuid,
        RequestType::TCP,
    );
    context_builder.add_httparse_to_trx(authorized, None, remote_ip);
    let trx_context = context_builder.build().unwrap();
    tx_sender
        .send(LogHandlerMessage::new_log_message(trx_context))
        .unwrap()
}
