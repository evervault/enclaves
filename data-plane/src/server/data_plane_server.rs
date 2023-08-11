use super::error::TlsError;
use super::http::ContentEncoding;
use super::tls::TlsServerBuilder;

use crate::base_tls_client::ClientError;
use crate::e3client::DecryptRequest;
use crate::e3client::{self, AuthRequest, E3Client};
use crate::error::Error::{ApiKeyInvalid, MissingApiKey};
use crate::error::{AuthError, Result};
use crate::{CageContext, FeatureContext, FEATURE_CONTEXT};

use crate::utils::trx_handler::{start_log_handler, LogHandlerMessage};

use bytes::Bytes;
use futures::StreamExt;

use httparse::Status;
use hyper::http::{self, request, HeaderName, HeaderValue};
use hyper::{Body, HeaderMap, Request, Response};
use sha2::Digest;
use shared::logging::TrxContextBuilder;
use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use shared::utils::pipe_streams;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::server::TlsStream;

use log::{debug, error, info, warn};

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

    info!("TLS Server Created - Listening for new connections.");
    loop {
        let mut stream = match server.accept().await {
            Ok(stream) => stream,
            Err(tls_err) => {
                error!("An error occurred while accepting the incoming connection — {tls_err}");
                continue;
            }
        };

        let e3_client_for_connection = e3_client.clone();
        let tx_for_connection = tx.clone();
        tokio::spawn(async move {
            let e3_client_for_tcp = e3_client_for_connection.clone();
            let tx_for_tcp = tx_for_connection.clone();
            let remote_ip = stream.get_remote_addr();

            let mut buffer = Vec::new();
            loop {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut temp_chunk = [0; 1024];
                let mut req = httparse::Request::new(&mut headers);
                let chunk_size = match stream.read(&mut temp_chunk).await {
                    Ok(chunk_size) => chunk_size,
                    Err(e) => {
                        error!("Connection read error - {e:?}");
                        shutdown_conn(&mut stream).await;
                        break;
                    }
                };
                buffer.extend_from_slice(&temp_chunk[..chunk_size]);

                match req.parse(&buffer) {
                    Ok(Status::Complete(body_offset)) => {
                        let headers = &req.headers;
                        let is_websocket = headers.iter().any(|header| {
                            header.name.to_ascii_lowercase() == "upgrade"
                                && header.value.to_ascii_lowercase() == "websocket".as_bytes()
                        });
                        let not_http = req.method.is_none();
                        if is_websocket || not_http {
                            //TODO: send 401 response
                            if let Err(err) =
                                auth_request_non_http(headers, e3_client_for_tcp.clone()).await
                            {
                                error!("Failed to authenticate request — {err:?}");
                                shutdown_conn(&mut stream).await;
                                break;
                            }
                            if let Err(err) =
                                pipe_to_customer_process(&mut stream, &buffer, port).await
                            {
                                warn!("Failed piping WS stream to customer process — {err:?}");
                                shutdown_conn(&mut stream).await;
                                break;
                            }
                        } else {
                            let request: Request<Body> =
                                match build_http_request(req, &buffer[body_offset..], port) {
                                    Ok(request) => request,
                                    Err(e) => {
                                        error!("Connection read error - {e:?}");
                                        shutdown_conn(&mut stream).await;
                                        break;
                                    }
                                };
                            match handle_http_request(
                                request,
                                e3_client_for_tcp.clone(),
                                tx_for_tcp.clone(),
                                remote_ip.clone(),
                                port,
                            )
                            .await
                            {
                                Ok(res) => {
                                    let response_bytes = response_to_bytes(res).await;
                                    let _ = stream.write_all(&response_bytes).await;
                                    shutdown_conn(&mut stream).await;
                                    break;
                                }
                                Err(err) => {
                                    error!(
                                        "Failed sending HTTP request to customer process — {err:?}"
                                    );
                                    shutdown_conn(&mut stream).await;
                                    break;
                                }
                            }
                        }
                    }
                    Ok(Status::Partial) => continue,
                    Err(_) => {
                        // We need to figure out a better auth mechanism for other protocols
                        if feature_context.api_key_auth {
                            error!("API key auth needs to be turned off for non HTTPS/WS streams");
                            shutdown_conn(&mut stream).await;
                            break;
                        }
                        if let Err(err) = pipe_to_customer_process(&mut stream, &buffer, port).await
                        {
                            warn!("Failed piping non HTTP/WS stream to customer process — {err:?}");
                            shutdown_conn(&mut stream).await;
                            break;
                        }
                    }
                }
            }
        });
    }
}

async fn auth_request_non_http(
    headers: &[httparse::Header<'_>],
    e3_client: Arc<E3Client>,
) -> Result<()> {
    let api_key = headers
        .iter()
        .find(|header| header.name.to_ascii_lowercase() == "api-key")
        .ok_or(MissingApiKey)?;
    let header_value = HeaderValue::from_bytes(api_key.value)?;
    if FeatureContext::get().api_key_auth
        && auth_request(header_value, CageContext::get()?, e3_client.clone())
            .await
            .is_some()
    {
        return Err(ApiKeyInvalid);
    }
    Ok(())
}

async fn shutdown_conn<L>(stream: &mut TlsStream<L>)
where
    TlsStream<L>: AsyncWriteExt + Unpin,
{
    if let Err(e) = stream.shutdown().await {
        error!("Failed to shutdown data plane connection — {e:?}");
    }
}

async fn pipe_to_customer_process<L>(
    stream: &mut TlsStream<L>,
    buffer: &[u8],
    port: u16,
) -> Result<()>
where
    TlsStream<L>: AsyncReadExt + Unpin + AsyncWrite,
{
    let mut customer_stream = TcpStream::connect(("127.0.0.1", port)).await?;
    customer_stream.write_all(buffer).await?;
    pipe_streams(stream, customer_stream).await?;
    Ok(())
}

fn build_http_request(
    request: httparse::Request<'_, '_>,
    body_buffer: &[u8],
    port: u16,
) -> Result<Request<Body>> {
    let uri = format!("http://127.0.0.1:{}{}", port, request.path.unwrap_or("/"));
    let mut header_map = HeaderMap::new();
    for header in request.headers {
        header_map.insert(
            HeaderName::from_str(header.name)?,
            HeaderValue::from_bytes(header.value)?,
        );
    }

    let mut req = Request::builder()
        .uri(uri)
        .method(request.method.unwrap())
        .body(Body::from(body_buffer.to_vec()))?;
    *req.headers_mut() = header_map;
    Ok(req)
}

async fn response_to_bytes(response: Response<Body>) -> Vec<u8> {
    let mut bytes = Vec::new();

    let status_line = format!(
        "{:?} {} {}\r\n",
        response.version(),
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    );
    bytes.extend_from_slice(status_line.as_bytes());

    for (header_name, header_value) in response.headers() {
        let header_str = format!(
            "{}: {}\r\n",
            header_name.as_str(),
            header_value.to_str().unwrap_or("")
        );
        bytes.extend_from_slice(header_str.as_bytes());
    }

    bytes.extend_from_slice(b"\r\n");

    let body_bytes: Bytes = hyper::body::to_bytes(response.into_body())
        .await
        .unwrap_or_else(|_| Bytes::new());

    bytes.extend_from_slice(&body_bytes);

    bytes
}

async fn handle_http_request(
    mut req: Request<Body>,
    e3_client_for_tcp: Arc<E3Client>,
    tx_for_tcp: UnboundedSender<LogHandlerMessage>,
    remote_ip: Option<String>,
    port: u16,
) -> Result<Response<Body>> {
    let e3_client_for_req = e3_client_for_tcp.clone();
    let feature_context = FeatureContext::get();
    let cage_context = CageContext::get()?;
    let tx_for_req = tx_for_tcp.clone();
    let remote_ip = remote_ip.clone();
    let request_timer = TrxContextBuilder::get_timer();
    let mut trx_context = init_trx(&cage_context, &feature_context, &req);
    let trx_id = trx_context.get_trx_id();
    if remote_ip.is_some() {
        trx_context.remote_ip(remote_ip.clone());
        add_remote_ip_to_forwarded_for_header(&mut req, remote_ip.as_deref().unwrap());
    }

    let trx_logging_enabled = feature_context.trx_logging_enabled;

    if trx_logging_enabled {
        add_ev_ctx_header_to_request(&mut req, &trx_id);
    }

    let mut response = handle_incoming_request(
        req,
        port,
        e3_client_for_req,
        cage_context.clone(),
        feature_context.clone(),
        &mut trx_context,
    )
    .await;

    let trusted_headers = FeatureContext::get().trusted_headers;
    trx_context.add_res_to_trx_context(&response, trusted_headers.as_ref());
    let built_context = trx_context.stop_timer_and_build(request_timer);

    match built_context {
        Ok(ctx) => {
            if trx_logging_enabled {
                //Add trx ID to response of request
                add_ev_ctx_header_to_response(&mut response, &trx_id);

                //Send trx to config server in data plane
                if let Err(e) = tx_for_req.send(LogHandlerMessage::new_log_message(ctx)) {
                    error!("Failed to send transaction context to log handler. err: {e}")
                }
            }
        }
        Err(e) => error!("Failed to build transaction context. err: {e:?}"),
    };

    Ok(response)
}

async fn auth_request(
    api_key: HeaderValue,
    cage_context: CageContext,
    e3_client: Arc<E3Client>,
) -> Option<Response<Body>> {
    debug!("Authenticating request");

    let hashed_api_key = match HeaderValue::from_bytes(&compute_base64_sha512(api_key.as_bytes())) {
        Ok(hashed_api_key_header) => hashed_api_key_header,
        Err(_) => return Some(build_error_response(Some("Invalid API Key.".to_string()))),
    };

    let auth_payload_for_hashed_api_key = AuthRequest::from(&cage_context);

    let auth_payload_for_app_api_key = AuthRequest {
        team_uuid: cage_context.team_uuid().to_string(),
        app_uuid: cage_context.app_uuid().to_string(),
        cage_uuid: None,
    };

    match e3_client
        .authenticate(&hashed_api_key, auth_payload_for_hashed_api_key)
        .await
    {
        Ok(auth_status) => {
            if !auth_status {
                info!("Failed to authenticate request using provided API Key");
                let response: Response<Body> = AuthError::FailedToAuthenticateApiKey.into();
                Some(response)
            } else {
                None
            }
        }
        Err(ClientError::FailedRequest(status)) if status.as_u16() == 401 => {
            //Temporary fallback to authenticate with APP api key -- remove this match when moving to just scoped api keys
            debug!("Failed to auth with scoped api key hash, attempting with app api key");
            match e3_client
                .authenticate(&api_key, auth_payload_for_app_api_key)
                .await
            {
                Ok(auth_status) => {
                    if !auth_status {
                        info!("Failed to authenticate request using provided API Key");
                        let response: Response<Body> = AuthError::FailedToAuthenticateApiKey.into();
                        Some(response)
                    } else {
                        None
                    }
                }
                Err(ClientError::FailedRequest(status)) if status.as_u16() == 401 => {
                    let response: Response<Body> = AuthError::FailedToAuthenticateApiKey.into();
                    Some(response)
                }
                Err(e) => {
                    error!("Failed to authenticate against e3 — {e:?}");
                    Some(build_error_response(Some(
                        "Connection to E3 failed.".to_string(),
                    )))
                }
            }
        }
        Err(e) => {
            error!("Failed to authenticate against e3 — {e:?}");
            Some(build_error_response(Some(
                "Connection to E3 failed.".to_string(),
            )))
        }
    }
}

async fn handle_incoming_request(
    req: Request<Body>,
    customer_port: u16,
    e3_client: Arc<E3Client>,
    cage_context: CageContext,
    feature_context: FeatureContext,
    trx_context: &mut TrxContextBuilder,
) -> Response<Body> {
    // Extract API Key header and authenticate request
    // Run parser over payload
    // Serialize request onto socket

    if feature_context.api_key_auth {
        debug!("Authenticating request");
        let api_key = match req
            .headers()
            .get(hyper::http::header::HeaderName::from_static("api-key"))
            .ok_or(AuthError::NoApiKeyGiven)
            .map(|api_key_header| api_key_header.to_owned())
        {
            Ok(api_key_header) => api_key_header,
            Err(e) => return e.into(),
        };

        if let Some(response) = auth_request(api_key, cage_context, e3_client.clone()).await {
            return response;
        }
    };

    let (req_info, req_body) = req.into_parts();

    let compression = req_info
        .headers
        .get(http::header::CONTENT_ENCODING)
        .map(ContentEncoding::try_from)
        .and_then(|encoding_res| encoding_res.ok());

    if let Some(_encoding) = req_info.headers.get(http::header::TRANSFER_ENCODING) {
        build_error_response(None)
    } else {
        handle_standard_request(
            (req_info, req_body),
            compression,
            customer_port,
            e3_client,
            trx_context,
        )
        .await
    }
}

pub async fn handle_standard_request(
    req_parts: (request::Parts, Body),
    _compression: Option<super::http::ContentEncoding>,
    customer_port: u16,
    e3_client: Arc<E3Client>,
    trx_context: &mut TrxContextBuilder,
) -> Response<Body> {
    let (mut req_info, req_body) = req_parts;
    let request_bytes = match hyper::body::to_bytes(req_body).await {
        Ok(body_bytes) => body_bytes,
        Err(e) => {
            error!("Failed to read entire body — {e}");
            return build_error_response(None);
        }
    };

    let decryption_payload = match extract_ciphertexts_from_payload(&request_bytes).await {
        Ok(decryption_res) => decryption_res,
        Err(_e) => {
            let response = build_error_response(Some(
                "Failed to parse incoming stream for ciphertexts".to_string(),
            ));
            return response;
        }
    };

    let n_decrypts: Option<u32> = decryption_payload.len().try_into().ok();

    let mut bytes_vec = request_bytes.to_vec();
    if !decryption_payload.is_empty() {
        let request_payload =
            e3client::CryptoRequest::new(serde_json::Value::Array(decryption_payload));
        let decrypted: DecryptRequest = match e3_client
            .decrypt_with_retries(2, request_payload)
            .await
        {
            Ok(decrypted) => decrypted,
            Err(e) => {
                error!("Failed to decrypt — {e}");
                return build_error_response(Some(format!("Failed to decrypt ciphertexts {e}")));
            }
        };

        debug!("Decryption complete");
        decrypted.data().iter().rev().for_each(|entry| {
            let range = entry.range();
            let value_in_bytes = serde_json::to_vec(entry.value());
            match value_in_bytes {
                Ok(value) => {
                    let _: Vec<u8> = bytes_vec.splice(range.0..range.1, value).collect();
                }
                Err(err) => {
                    warn!("Failed to convert Json Value into bytes. Error {err}");
                }
            }
        });
    }

    trx_context.n_decrypted_fields(n_decrypts);

    // Build processed request
    let mut uri_builder = hyper::Uri::builder()
        .authority(format!("0.0.0.0:{customer_port}"))
        .scheme("http");
    if let Some(req_path) = req_info.uri.path_and_query() {
        uri_builder = uri_builder.path_and_query(req_path.clone());
    }
    req_info.uri = uri_builder.build().expect("rebuilt from existing request");
    req_info
        .headers
        .insert("Content-Length", HeaderValue::from(bytes_vec.len()));

    let decrypted_request = Request::from_parts(req_info, Body::from(bytes_vec));
    debug!("Finished processing request");
    let http_client = hyper::Client::new();
    match http_client.request(decrypted_request).await {
        Ok(res) => res,
        Err(e) => {
            let msg = format!("Error requesting user process - {e}");
            error!("Error forwarding request to user process: {msg}");
            build_error_response(Some(msg))
        }
    }
}

async fn extract_ciphertexts_from_payload(
    incoming_payload: &[u8],
) -> Result<Vec<serde_json::Value>> {
    let mut stream_reader =
        crate::crypto::stream::IncomingStreamDecoder::create_reader(incoming_payload);

    let mut decryption_payload = vec![];
    while let Some(parsed_frame) = stream_reader.next().await {
        let (range, ciphertext) = match parsed_frame? {
            crate::crypto::stream::IncomingFrame::Ciphertext(ciphertext) => ciphertext,
            _ => continue,
        };

        let ciphertext_item = serde_json::json!({
            "range": range,
            "value": ciphertext.to_string()
        });
        decryption_payload.push(ciphertext_item);
    }
    Ok(decryption_payload)
}

fn init_trx(
    cage_context: &CageContext,
    feature_context: &FeatureContext,
    req: &Request<Body>,
) -> TrxContextBuilder {
    let mut trx_ctx = TrxContextBuilder::init_trx_context_with_cage_details(
        &cage_context.cage_uuid,
        &cage_context.cage_name,
        &cage_context.app_uuid,
        &cage_context.team_uuid,
    );
    trx_ctx.add_req_to_trx_context(req, &feature_context.trusted_headers);
    trx_ctx
}

fn build_header_value_from_str(header_val: &str) -> HeaderValue {
    HeaderValue::from_str(header_val).expect("Unable to create headerValue from str")
}

fn add_ev_ctx_header_to_request(req: &mut Request<Body>, trx_id: &str) {
    req.headers_mut()
        .insert("x-evervault-cage-ctx", build_header_value_from_str(trx_id));
}

fn append_or_insert_header(
    header: &str,
    req: &mut Request<Body>,
    value: &str,
) -> std::result::Result<(), http::header::InvalidHeaderName> {
    let header_name = http::header::HeaderName::from_str(header)?;
    if let Some(header_val) = req
        .headers_mut()
        .get(&header_name)
        .and_then(|header_val| header_val.to_str().ok())
    {
        let updated_header = format!("{header_val}, {value}");
        req.headers_mut()
            .insert(header_name, build_header_value_from_str(&updated_header));
    } else {
        req.headers_mut()
            .insert(header_name, build_header_value_from_str(value));
    }
    Ok(())
}

fn add_remote_ip_to_forwarded_for_header(req: &mut Request<Body>, remote_ip: &str) {
    let _ = append_or_insert_header("X-Forwarded-For", req, remote_ip);
    let _ = append_or_insert_header("X-Forwarded-Proto", req, "https");
    let forwarded_header = format!("for={remote_ip};proto=https");
    let _ = append_or_insert_header("Forwarded", req, &forwarded_header);
}

fn add_ev_ctx_header_to_response(response: &mut Response<Body>, trx_id: &str) {
    response
        .headers_mut()
        .insert("x-evervault-cage-ctx", build_header_value_from_str(trx_id));
}

fn build_error_response(body_msg: Option<String>) -> Response<Body> {
    let body = match body_msg {
        Some(msg) => Body::from(msg),
        None => Body::empty(),
    };

    Response::builder()
        .status(500)
        .body(body)
        .expect("Hardcoded response")
}

pub fn compute_base64_sha512(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(input.as_ref());
    let hash_digest = base64::encode(hasher.finalize().as_slice());
    hash_digest.as_bytes().to_vec()
}

#[cfg(test)]
mod test {
    use hyper::{http::HeaderValue, Body, Request, Response};

    use crate::server::data_plane_server::compute_base64_sha512;

    use super::{
        add_ev_ctx_header_to_request, add_ev_ctx_header_to_response,
        extract_ciphertexts_from_payload,
    };

    #[tokio::test]
    async fn test_extract_ciphertexts_with_none_present() {
        let input = b"this is an input string which has no sign of our ciphertexts";
        let result = extract_ciphertexts_from_payload(input).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_extract_ciphertexts_with_one_present() {
        let input = b"this is an input string which has one ev:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$ of our ciphertexts";
        let result = extract_ciphertexts_from_payload(input).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_adding_ctx_header_to_req() {
        let mut request = Request::builder()
            .method("GET")
            .uri("https://evervault.com/")
            .body(Body::empty())
            .unwrap();

        let trx_id = format!("{:X}", u128::MAX);

        add_ev_ctx_header_to_request(&mut request, &trx_id);

        let ctx_header = request.headers().get("x-evervault-cage-ctx");
        let expected_header_val = HeaderValue::from_str(trx_id.as_str())
            .expect("Unable to create headerValue from ID: u128");

        assert!(ctx_header.is_some());
        assert_eq!(ctx_header.unwrap(), expected_header_val);
    }

    #[test]
    fn test_adding_ctx_header_to_res() {
        let mut response = Response::builder()
            .status("200")
            .body(Body::empty())
            .unwrap();

        let trx_id = format!("{:X}", u128::MAX);

        add_ev_ctx_header_to_response(&mut response, &trx_id);

        let ctx_header = response.headers().get("x-evervault-cage-ctx");
        let expected_header_val = HeaderValue::from_str(trx_id.as_str())
            .expect("Unable to create headerValue from ID: u128");

        assert!(ctx_header.is_some());
        assert_eq!(ctx_header.unwrap(), expected_header_val);
    }

    #[test]
    fn test_compute_sha_512() {
        let test_input = "ev:key:1:1f31f1Lpz8jWyc8CcYQBH5GOwimvDaa3sJiIESsPH8j79xvKF";
        let test_output = "bAJwONVQChhErjXlPJfPp3d6Hss43rjFAZcXhyVTcAaO7VY0bEeIBhA3HUN6z56EAAHU7+w1bCTHf6+Vg7y3/g==".as_bytes().to_vec();

        let output_bytes = compute_base64_sha512(test_input);

        assert_eq!(test_output, output_bytes);
    }
}
