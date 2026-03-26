use super::error::TlsError;
use super::http::parse::{try_parse_http_request_from_stream, Incoming};
use super::http::{request_to_bytes, response_to_bytes};
use super::tls::TlsServerBuilder;

use crate::e3client::{E3Api, E3Client};
use crate::env::{EnvironmentLoader, NeedCert};
use crate::server::http::{build_internal_error_response, parse};
use crate::{EnclaveContext, FeatureContext};

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
    auth::{auth_request as send_auth_request, AuthError, AuthLayer},
    context_log::{init_request_context, ContextLogLayer},
    decrypt::DecryptLayer,
    forward::ForwardService,
};

pub async fn run<L: Listener + Send + Sync>(
    tcp_server: L,
    port: u16,
    context: FeatureContext,
    env_loader: EnvironmentLoader<NeedCert>,
) -> Result<(), TlsError>
where
    TlsError: From<<L as Listener>::Error>,
    <L as Listener>::Connection: ProxiedConnection + 'static,
{
    let mut server = TlsServerBuilder::new()
        .with_server(tcp_server)
        .with_attestable_cert(env_loader)
        .await?;
    let e3_client = Arc::new(E3Client::new());

    let (tx, rx): (
        UnboundedSender<LogHandlerMessage>,
        UnboundedReceiver<LogHandlerMessage>,
    ) = unbounded_channel();

    let feature_context = Arc::new(context);
    if feature_context.trx_logging_enabled {
        let tx_for_handler = tx.clone();
        tokio::spawn(async move {
            start_log_handler(tx_for_handler, rx).await;
        });
    }

    log::info!("TLS Server Created - Listening for new connections.");
    let enclave_context = match EnclaveContext::get() {
        Ok(context) => Arc::new(context),
        Err(e) => {
            log::error!("Failed to read enclave context in data plane server - {e}");
            return Err(e.into());
        }
    };
    let service_builder = tower::ServiceBuilder::new();

    // Only apply attestation layer in enclave mode
    #[cfg(feature = "enclave")]
    let service_builder = service_builder.layer(AttestLayer::new(feature_context.clone()));

    // layers are invoked in the order that they're registered to the service
    let service = service_builder
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
        let enclave_context_clone = enclave_context.clone();
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
                            enclave_context_clone.clone(),
                            feature_context_clone.clone(),
                            e3_client_clone.clone(),
                            port,
                        )
                        .await;
                    }
                    Ok(Incoming::HttpRequest(request)) => {
                        let response = data_plane_service.call(request).await.unwrap_or_else(|e| {
                            log::error!("Failed to handle incoming request in data plane - {e:?}");
                            build_internal_error_response(None)
                        });
                        let response_bytes = response_to_bytes(response).await;
                        let _ = stream.write_all(&response_bytes).await;
                        continue;
                    }
                    Ok(Incoming::NonHttpRequest(_)) if feature_context_clone.api_key_auth => {
                        log::info!(
                            "Non http request received with auth enabled, closing connection"
                        );
                        log_non_http_trx(&tx_for_connection, false, remote_ip, None);
                        shutdown_conn(&mut stream).await;
                        return;
                    }
                    Ok(Incoming::NonHttpRequest(bytes)) => {
                        log::info!(
                            "Non http request received with auth enabled, closing connection"
                        );
                        log_non_http_trx(&tx_for_connection, true, remote_ip, None);
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
    #[allow(unreachable_code)]
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_websocket_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
    request: Request<Body>,
    tx_for_connection: &UnboundedSender<LogHandlerMessage>,
    remote_ip: Option<String>,
    enclave_context: Arc<EnclaveContext>,
    feature_context: Arc<FeatureContext>,
    e3_client: Arc<E3Client>,
    port: u16,
) {
    let context_builder = init_request_context(
        &request,
        enclave_context.clone(),
        feature_context.clone(),
        RequestType::Websocket,
    );

    if let Err(e) =
        authenticate_websocket_request(&request, enclave_context, e3_client, &feature_context).await
    {
        let response_bytes = response_to_bytes(e.into()).await;
        log_non_http_trx(tx_for_connection, false, remote_ip, Some(context_builder));
        let _ = stream.write_all(&response_bytes).await;
        return;
    }

    log_non_http_trx(tx_for_connection, true, remote_ip, Some(context_builder));
    let serialized_request = request_to_bytes(request).await;
    let _ = pipe_to_customer_process(stream, &serialized_request, port).await;
}

async fn authenticate_websocket_request<T: E3Api + Send + Sync + 'static>(
    request: &Request<Body>,
    enclave_context: Arc<EnclaveContext>,
    e3_client: Arc<T>,
    feature_context: &Arc<FeatureContext>,
) -> Result<(), AuthError> {
    if !feature_context.api_key_auth {
        return Ok(());
    }

    let api_key = request
        .headers()
        .get("api-key")
        .ok_or(AuthError::NoApiKeyGiven)?;

    send_auth_request(api_key, enclave_context, e3_client).await?;

    Ok(())
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
    context_builder: Option<TrxContextBuilder>,
) {
    let enclave_context = EnclaveContext::get().unwrap();
    let mut context_builder = match context_builder {
        Some(context_builder) => context_builder,
        _ => TrxContextBuilder::init_trx_context_with_enclave_details(
            &enclave_context.uuid,
            &enclave_context.name,
            &enclave_context.app_uuid,
            &enclave_context.team_uuid,
            RequestType::TCP,
        ),
    };
    context_builder.add_httparse_to_trx(authorized, None, remote_ip);
    let trx_context = context_builder.build().unwrap();
    tx_sender
        .send(LogHandlerMessage::new_log_message(trx_context))
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        base_tls_client::ClientError,
        e3client::{mock::MockE3TestClient, AuthRequest},
        server::layers::auth::compute_base64_sha512,
    };
    use hyper::{header::HeaderValue, StatusCode};
    #[cfg(feature = "network_egress")]
    use shared::server::egress::{EgressConfig, EgressDestinations};
    use std::sync::Arc;

    fn create_default_feature_ctx(api_key_auth: bool) -> FeatureContext {
        FeatureContext {
            api_key_auth,
            healthcheck: std::default::Default::default(),
            healthcheck_port: std::default::Default::default(),
            healthcheck_use_tls: std::default::Default::default(),
            trx_logging_enabled: std::default::Default::default(),
            forward_proxy_protocol: std::default::Default::default(),
            trusted_headers: std::default::Default::default(),
            attestation_cors: std::default::Default::default(),
            #[cfg(feature = "network_egress")]
            egress: EgressConfig {
                allow_list: EgressDestinations {
                    wildcard: std::default::Default::default(),
                    exact: std::default::Default::default(),
                    allow_all: std::default::Default::default(),
                    ips: std::default::Default::default(),
                },
            },
        }
    }

    #[tokio::test]
    async fn test_websocket_authenticate_request_successfully() {
        let mut request = Request::new(Body::empty());

        let api_key = "api-key";
        let mut headers = hyper::HeaderMap::new();
        headers.append("api-key", HeaderValue::from_str(api_key).unwrap());
        request.headers_mut().extend(headers);

        let enclave_ctx = Arc::new(EnclaveContext {
            team_uuid: "team_uuid".into(),
            app_uuid: "app_uuid".into(),
            uuid: "enclave_uuid".into(),
            name: "my-enclave".into(),
        });

        let expected_auth_req = AuthRequest::from(enclave_ctx.clone());
        let hashed_api_key = compute_base64_sha512(api_key.as_bytes());
        let auth_challenge = HeaderValue::from_bytes(&hashed_api_key).unwrap();

        let mut e3_test_client = MockE3TestClient::new();
        e3_test_client
            .expect_authenticate()
            .return_once(move |val, context| {
                assert_eq!(val, auth_challenge);
                assert_eq!(context, expected_auth_req);
                Ok(())
            });

        let feature_context = Arc::new(create_default_feature_ctx(true));

        let result = authenticate_websocket_request(
            &request,
            enclave_ctx,
            Arc::new(e3_test_client),
            &feature_context,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_websocket_authenticate_request_no_api_key() {
        let request = Request::new(Body::empty());

        let enclave_ctx = Arc::new(EnclaveContext {
            team_uuid: "team_uuid".into(),
            app_uuid: "app_uuid".into(),
            uuid: "enclave_uuid".into(),
            name: "my-enclave".into(),
        });

        let mut e3_test_client = MockE3TestClient::new();
        e3_test_client.expect_authenticate().never();

        let feature_context = Arc::new(create_default_feature_ctx(true));

        let result = authenticate_websocket_request(
            &request,
            enclave_ctx,
            Arc::new(e3_test_client),
            &feature_context,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::NoApiKeyGiven));
    }

    #[tokio::test]
    async fn test_websocket_authenticate_request_failure() {
        let mut request = Request::new(Body::empty());

        let api_key = "api-key";
        let mut headers = hyper::HeaderMap::new();
        headers.append("api-key", HeaderValue::from_str(api_key).unwrap());
        request.headers_mut().extend(headers);

        let enclave_ctx = Arc::new(EnclaveContext {
            team_uuid: "team_uuid".into(),
            app_uuid: "app_uuid".into(),
            uuid: "enclave_uuid".into(),
            name: "my-enclave".into(),
        });

        let expected_auth_req = AuthRequest::from(enclave_ctx.clone());
        let hashed_api_key = compute_base64_sha512(api_key.as_bytes());
        let auth_challenge = HeaderValue::from_bytes(&hashed_api_key).unwrap();

        let enclave_ctx = Arc::new(EnclaveContext {
            team_uuid: "team_uuid".into(),
            app_uuid: "app_uuid".into(),
            uuid: "enclave_uuid".into(),
            name: "my-enclave".into(),
        });

        let mut e3_test_client = MockE3TestClient::new();
        e3_test_client
            .expect_authenticate()
            .return_once(move |val, context| {
                assert_eq!(val, auth_challenge);
                assert_eq!(context, expected_auth_req);
                Err(ClientError::FailedRequest(StatusCode::UNAUTHORIZED))
            });

        let feature_context = Arc::new(create_default_feature_ctx(true));

        let result = authenticate_websocket_request(
            &request,
            enclave_ctx,
            Arc::new(e3_test_client),
            &feature_context,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::FailedToAuthenticateApiKey
        ));
    }

    #[tokio::test]
    async fn test_websocket_auth_disabled() {
        let request = Request::new(Body::empty());

        let enclave_ctx = Arc::new(EnclaveContext {
            team_uuid: "team_uuid".into(),
            app_uuid: "app_uuid".into(),
            uuid: "enclave_uuid".into(),
            name: "my-enclave".into(),
        });

        let mut e3_test_client = MockE3TestClient::new();
        e3_test_client.expect_authenticate().never();

        let feature_context = Arc::new(create_default_feature_ctx(false));

        let result = authenticate_websocket_request(
            &request,
            enclave_ctx,
            Arc::new(e3_test_client),
            &feature_context,
        )
        .await;

        assert!(result.is_ok());
    }
}
