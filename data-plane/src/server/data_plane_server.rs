use super::error::TlsError;
use super::http::ContentEncoding;
use super::tls::TlsServerBuilder;

use crate::e3client::{self, DecryptRequest, E3Client, E3Error};
use crate::error::{AuthError, Result};
use crate::CageContext;

use futures::StreamExt;

use hyper::http::HeaderValue;
use hyper::http::{self, request::Parts};
use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};

use shared::server::Listener;
use std::sync::Arc;

macro_rules! create_tls_server_or_return {
    ($server:expr, $cert_name:expr) => {
        match TlsServerBuilder
            .with_server($server)
            .with_self_signed_cert($cert_name)
            .await
        {
            Ok(tls_server) => tls_server,
            Err(error) => return eprintln!("Error performing TLS upgrade: {error}"),
        }
    };
}

pub async fn run<L: Listener + Send + Sync>(tcp_server: L, port: u16)
where
    TlsError: From<<L as Listener>::Error>,
    <L as Listener>::Connection: 'static,
{
    let cage_context =
        Arc::new(CageContext::new().expect("Missing required Cage context elements"));
    let mut server = create_tls_server_or_return!(tcp_server, cage_context.get_cert_name());
    let http_server = conn::Http::new();
    let e3_client = Arc::new(E3Client::new());
    loop {
        let stream = match tokio::time::timeout(server.time_till_expiry(), server.accept()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(tls_err)) => {
                eprintln!(
                    "An error occurred while accepting the incoming connection — {}",
                    tls_err
                );
                continue;
            }
            Err(_) => {
                println!("Attestation document signing cert expired, recreating server...");
                server =
                    create_tls_server_or_return!(server.into_inner(), cage_context.get_cert_name());
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
                            handle_incoming_request(
                                req,
                                port,
                                e3_client_for_req,
                                cage_context_for_req,
                            )
                            .await
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
    cage_context: Arc<CageContext>,
) -> Result<Response<Body>> {
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
        Err(e) => return Ok(e.into()),
    };

    let is_auth = if cfg!(feature = "enclave") {
        println!("Authenticating request");
        match e3_client
            .authenticate(&api_key, cage_context.as_ref().into())
            .await
        {
            Ok(auth_status) => auth_status,
            Err(E3Error::FailedRequest(status)) if status.as_u16() == 401 => {
                return Ok(AuthError::FailedToAuthenticateApiKey.into());
            }
            Err(e) => {
                eprintln!("Failed to authenticate against e3 — {:?}", e);
                return Ok(Response::builder()
                    .status(500)
                    .body(Body::from("Connection to E3 failed."))
                    .expect("Hardcoded response"));
            }
        }
    } else {
        true
    };

    if !is_auth {
        println!("Failed to authenticate request using provided API Key");
        return Ok(AuthError::FailedToAuthenticateApiKey.into());
    }

    let (req_info, req_body) = req.into_parts();

    let compression = req_info
        .headers
        .get(http::header::CONTENT_ENCODING)
        .map(ContentEncoding::try_from)
        .and_then(|encoding_res| encoding_res.ok());

    if let Some(_encoding) = req_info.headers.get(http::header::TRANSFER_ENCODING) {
        Ok(Response::builder()
            .status(500)
            .body(Body::empty())
            .expect("Hardcoded response"))
    } else {
        handle_standard_request(
            &api_key,
            req_info,
            req_body,
            compression,
            customer_port,
            e3_client,
            cage_context,
        )
        .await
    }
}

pub async fn handle_standard_request(
    api_key: &HeaderValue,
    mut req_info: Parts,
    req_body: Body,
    _compression: Option<super::http::ContentEncoding>,
    customer_port: u16,
    e3_client: Arc<E3Client>,
    cage_context: Arc<CageContext>,
) -> crate::error::Result<Response<Body>> {
    let request_bytes = match hyper::body::to_bytes(req_body).await {
        Ok(body_bytes) => body_bytes,
        Err(e) => {
            eprintln!("Failed to read entire body — {}", e);
            return Ok(Response::builder()
                .status(500)
                .body(Body::empty())
                .expect("Hardcoded response"));
        }
    };

    let decryption_payload = match extract_ciphertexts_from_payload(&request_bytes).await {
        Ok(decryption_payload) => decryption_payload,
        Err(_e) => {
            return Ok(Response::builder()
                .status(500)
                .body(Body::from(
                    "Failed to parse incoming stream for ciphertexts",
                ))
                .expect("Hardcoded response"))
        }
    };

    let mut bytes_vec = request_bytes.to_vec();
    if !decryption_payload.is_empty() {
        let request_payload = e3client::CryptoRequest::from((
            serde_json::Value::Array(decryption_payload),
            cage_context.as_ref(),
        ));
        let decrypted: DecryptRequest = match e3_client.decrypt(api_key, request_payload).await {
            Ok(decrypted) => decrypted,
            Err(e) => {
                eprintln!("Failed to decrypt — {}", e);
                return Ok(Response::builder()
                    .status(500)
                    .body(Body::empty())
                    .expect("Hardcoded response"));
            }
        };

        println!("Decryption complete");
        decrypted.data().iter().rev().for_each(|entry| {
            let range = entry.range();
            let _: Vec<u8> = bytes_vec
                .splice(range.0..range.1, entry.value().bytes())
                .collect();
        });
    }

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
    let customer_response = match http_client.request(decrypted_request).await {
        Ok(res) => res,
        Err(e) => {
            let msg = format!("Error requesting user process - {}", e);
            eprintln!("{}", msg);
            let res_body = Body::from(msg);
            Response::builder()
                .status(500)
                .body(res_body)
                .expect("Hardcoded response")
        }
    };

    Ok(customer_response)
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
