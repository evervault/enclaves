use super::error::TlsError;
use super::http::ContentEncoding;
use super::tls::TlsServerBuilder;

use crate::base_tls_client::ClientError;
use crate::e3client::{self, AuthRequest, DecryptRequest, E3Client};
use crate::error::{AuthError, Result};
use crate::CageContext;

use futures::StreamExt;

use hyper::http::HeaderValue;
use hyper::http::{self, request::Parts};
use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};

use shared::logging::TrxContextBuilder;
use shared::server::Listener;
use std::sync::Arc;

pub async fn run<L: Listener + Send + Sync>(tcp_server: L, port: u16)
where
    TlsError: From<<L as Listener>::Error>,
    <L as Listener>::Connection: 'static,
{
    let cage_context = CageContext::try_from_env().expect("Missing required Cage context elements");
    let mut server = TlsServerBuilder::new()
        .with_server(tcp_server)
        .with_attestable_cert(cage_context.clone())
        .await
        .expect("Failed to create tls server");
    let http_server = conn::Http::new();
    let e3_client = Arc::new(E3Client::new());
    println!("TLS Server Created - Listening for new connections.");
    loop {
        let stream = match server.accept().await {
            Ok(stream) => stream,
            Err(tls_err) => {
                eprintln!(
                    "An error occurred while accepting the incoming connection — {}",
                    tls_err
                );
                continue;
            }
        };
        let server = http_server.clone();
        let e3_client_for_connection = e3_client.clone();
        let cage_context_for_connection = cage_context.clone();
        tokio::spawn(async move {
            let e3_client_for_tcp = e3_client_for_connection.clone();
            let cage_context_for_tcp = cage_context_for_connection.clone();
            let sent_response = server
                .serve_connection(
                    stream,
                    service_fn(|req: Request<Body>| {
                        let e3_client_for_req = e3_client_for_tcp.clone();
                        let cage_context_for_req = cage_context_for_tcp.clone();
                        async move {
                            let mut trx_context = init_trx(&cage_context_for_req, &req);
                            trx_context.add_req_to_trx_context(&req);
                            let response = handle_incoming_request(
                                req,
                                port,
                                e3_client_for_req,
                                cage_context_for_req,
                                &mut trx_context,
                            )
                            .await;

                            trx_context.add_res_to_trx_context(&response);
                            let built_context = trx_context.build();

                            match built_context {
                                Ok(ctx) => ctx.record_trx(),
                                Err(e) => {
                                    println!("Failed to build transaction context. err: {:?}", e)
                                }
                            };

                            let res: Result<Response<Body>> = Ok(response);
                            res
                        }
                    }),
                )
                .await;

            if let Err(processing_err) = sent_response {
                eprintln!(
                    "An error occurred while processing your request — {}",
                    processing_err
                );
            }
        });
    }
}

async fn handle_incoming_request(
    req: Request<Body>,
    customer_port: u16,
    e3_client: Arc<E3Client>,
    cage_context: CageContext,
    trx_context: &mut TrxContextBuilder,
) -> Response<Body> {
    // Extract API Key header and authenticate request
    // Run parser over payload
    // Serialize request onto socket
    let api_key = match req
        .headers()
        .get(hyper::http::header::HeaderName::from_static("api-key"))
        .ok_or(AuthError::NoApiKeyGiven)
        .map(|api_key_header| api_key_header.to_owned())
    {
        Ok(api_key_header) => api_key_header,
        Err(e) => return e.into(),
    };

    let is_auth = if cfg!(feature = "enclave") {
        println!("Authenticating request");
        match e3_client
            .authenticate(&api_key, AuthRequest::from(&cage_context))
            .await
        {
            Ok(auth_status) => auth_status,
            Err(ClientError::FailedRequest(status)) if status.as_u16() == 401 => {
                let response: Response<Body> = AuthError::FailedToAuthenticateApiKey.into();
                return response;
            }
            Err(e) => {
                eprintln!("Failed to authenticate against e3 — {:?}", e);
                return build_error_response(Some("Connection to E3 failed.".to_string()));
            }
        }
    } else {
        true
    };

    if !is_auth {
        println!("Failed to authenticate request using provided API Key");
        let response = AuthError::FailedToAuthenticateApiKey.into();
        return response;
    }

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
            &api_key,
            (req_info, req_body),
            compression,
            customer_port,
            e3_client,
            &cage_context,
            trx_context,
        )
        .await
    }
}

pub async fn handle_standard_request(
    api_key: &HeaderValue,
    req_parts: (Parts, Body),
    _compression: Option<super::http::ContentEncoding>,
    customer_port: u16,
    e3_client: Arc<E3Client>,
    cage_context: &CageContext,
    trx_context: &mut TrxContextBuilder,
) -> Response<Body> {
    let (mut req_info, req_body) = req_parts;
    let request_bytes = match hyper::body::to_bytes(req_body).await {
        Ok(body_bytes) => body_bytes,
        Err(e) => {
            eprintln!("Failed to read entire body — {}", e);
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
        let request_payload = e3client::CryptoRequest::from((
            serde_json::Value::Array(decryption_payload),
            cage_context,
        ));
        let decrypted: DecryptRequest = match e3_client.decrypt(api_key, request_payload).await {
            Ok(decrypted) => decrypted,
            Err(e) => {
                eprintln!("Failed to decrypt — {}", e);
                return build_error_response(Some(String::from("Failed to decrypt ciphertexts")));
            }
        };

        println!("Decryption complete");
        decrypted.data().iter().rev().for_each(|entry| {
            let range = entry.range();
            let value_in_bytes = serde_json::to_vec(entry.value());
            match value_in_bytes {
                Ok(value) => {
                    let _: Vec<u8> = bytes_vec.splice(range.0..range.1, value).collect();
                }
                Err(err) => {
                    eprintln!("Failed to convert Json Value into bytes. Error {}", err);
                }
            }
        });
    }

    trx_context.n_decrypts(n_decrypts);

    // Build processed request
    let mut uri_builder = hyper::Uri::builder()
        .authority(format!("0.0.0.0:{}", customer_port))
        .scheme("http");
    if let Some(req_path) = req_info.uri.path_and_query() {
        uri_builder = uri_builder.path_and_query(req_path.clone());
    }
    req_info.uri = uri_builder.build().expect("rebuilt from existing request");
    req_info
        .headers
        .insert("Content-Length", HeaderValue::from(bytes_vec.len()));
    let decrypted_request = Request::from_parts(req_info, Body::from(bytes_vec));
    println!("Finished processing request");
    let http_client = hyper::Client::new();
    match http_client.request(decrypted_request).await {
        Ok(res) => res,
        Err(e) => {
            let msg = format!("Error requesting user process - {}", e);
            eprintln!("{}", msg);
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

fn init_trx(cage_context: &CageContext, req: &Request<Body>) -> TrxContextBuilder {
    let mut trx_ctx = TrxContextBuilder::init_trx_context_with_cage_details(
        &cage_context.cage_uuid,
        &cage_context.cage_name,
        &cage_context.app_uuid,
        &cage_context.team_uuid,
    );
    trx_ctx.add_req_to_trx_context(req);
    trx_ctx
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

#[cfg(test)]
mod test {
    use super::extract_ciphertexts_from_payload;

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
}
