use futures::StreamExt;
use hyper::http::{Request, Response};
use hyper::Body;
use serde_json::Map;
use serde_json::Value;
use shared::logging::TrxContextBuilder;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tower::{Layer, Service};
use futures::future;

use crate::base_tls_client::ClientError;
use crate::e3client::{CryptoRequest, DecryptRequest, E3Api, E3Client};

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Failed to serialize request during decryption")]
    FailedToSerializeRequest,
    #[error("Failed to find ciphertexts in incoming stream - {0}")]
    CiphertextStreamError(#[from] crate::crypto::stream::IncomingStreamError),
    #[error("Error communicating with e3 during decrypt - {0}")]
    E3Error(#[from] crate::base_tls_client::ClientError),
}

impl DecryptError {
    fn to_status(&self) -> u16 {
        match self {
            Self::E3Error(ClientError::FailedRequest(code)) => code.as_u16(),
            _ => 500,
        }
    }
}

impl std::convert::From<DecryptError> for Response<Body> {
    fn from(err: DecryptError) -> Self {
        let msg = err.to_string();
        let body = serde_json::json!({
          "message": msg
        })
        .to_string();
        Response::builder()
            .status(err.to_status())
            .header("content-length", body.len())
            .body(body.into())
            .expect("Failed to build auth error to response")
    }
}

#[derive(Clone)]
pub struct DecryptLayer<T: E3Api + Send + Sync + 'static>
where
    T: E3Api + Send + Sync + 'static,
{
    e3_client: Arc<T>,
}

impl<T: E3Api + Send + Sync + 'static> DecryptLayer<T> {
    pub fn new(e3_client: Arc<T>) -> Self {
        Self { e3_client }
    }
}

impl<S, T: E3Api + Send + Sync + 'static> Layer<S> for DecryptLayer<T> {
    type Service = DecryptService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        DecryptService {
            e3_client: self.e3_client.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct DecryptService<S, T> {
    e3_client: Arc<T>,
    inner: S,
}

impl<S, T> Service<Request<Body>> for DecryptService<S, T>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: 'static,
    T: E3Api + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    // Service is always ready to receive requests
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let e3_client = self.e3_client.clone();
        Box::pin(async move {
            let mut context = req
                .extensions_mut()
                .remove::<TrxContextBuilder>()
                .expect("No context set on received request");
            let (mut req_info, req_body) = req.into_parts();
            let encrypted_headers: Vec<Value> = req_info
                .headers
                .clone()
                .into_iter()
                .filter_map(|(header_name, header_value)| {
                    let header_val = header_value.to_str().unwrap();
                    if header_val.starts_with("ev:") {
                        let mut test: Map<String, Value> = Map::new();
                        test.insert(
                            header_name.clone().unwrap().to_string(),
                            serde_json::Value::String(header_val.to_string()),
                        );
                        println!("test {:?}", test);
                        Some(serde_json::Value::Object(test))
                    } else {
                        None
                    }
                })
                .collect();
            let request_bytes = match hyper::body::to_bytes(req_body).await {
                Ok(body_bytes) => body_bytes,
                Err(e) => {
                    log::error!("Failed to read entire body — {e}");
                    let mut error_response: Response<Body> =
                        DecryptError::FailedToSerializeRequest.into();
                    error_response.extensions_mut().insert(context);
                    return Ok(error_response);
                }
            };

            req_info.headers.remove("transfer-encoding");

            let decryption_payload = match extract_ciphertexts_from_payload(&request_bytes).await {
                Ok(decryption_res) => decryption_res,
                Err(e) => {
                    log::error!(
                        "An error occurred while parsing the incoming stream for ciphertexts - {e}"
                    );
                    let mut error_response: Response<Body> = e.into();
                    error_response.extensions_mut().insert(context);
                    return Ok(error_response);
                }
            };

            let n_decrypts: Option<u32> = decryption_payload.len().try_into().ok();

            let mut bytes_vec = request_bytes.to_vec();
            if !decryption_payload.is_empty() || !encrypted_headers.is_empty() {
                let request_payload = CryptoRequest::new(
                    serde_json::Value::Array(decryption_payload),
                    Some(serde_json::Value::Array(encrypted_headers)),
                );
                println!("About to decrypt");
                let decrypted: DecryptRequest =
                    match e3_client.decrypt_with_retries(2, request_payload).await {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            log::error!("Failed to decrypt — {e}");
                            let mut error_response: Response<Body> = DecryptError::from(e).into();
                            error_response.extensions_mut().insert(context);
                            return Ok(error_response);
                        }
                    };

                log::info!("Decryption complete, rebuilding request");
                inject_decrypted_values_into_request_vec(&decrypted, &mut bytes_vec);
                req_info
                    .headers
                    .insert("content-length", bytes_vec.len().into());
            }
            let mut decrypted_request = hyper::Request::from_parts(req_info, Body::from(bytes_vec));
            context.n_decrypted_fields(n_decrypts);
            decrypted_request.extensions_mut().insert(context);
            inner.call(decrypted_request).await
        })
    }
}

fn swap_encrypted_headers(
    req: &mut Request<Body>,
    encrypted_headers: Vec<(
        Option<hyper::header::HeaderName>,
        hyper::header::HeaderValue,
    )>,
) {
    encrypted_headers
        .iter()
        .for_each(|(header_name, header_value)| {
            req.headers_mut()
                .insert(header_name.clone().unwrap(), header_value.clone());
        });
}

fn inject_decrypted_values_into_request_vec(
    decrypted_values: &DecryptRequest,
    request_bytes: &mut Vec<u8>,
) {
    decrypted_values.body_data().iter().rev().for_each(|entry| {
        let range = entry.range();
        let value_in_bytes = serde_json::to_vec(entry.value());
        match value_in_bytes {
            Ok(value) => {
                let _: Vec<u8> = request_bytes.splice(range.0..range.1, value).collect();
            }
            Err(err) => {
                log::error!("Failed to convert Json Value into bytes. Error {err}");
            }
        }
    });
}

async fn extract_ciphertexts_from_payload(
    incoming_payload: &[u8],
) -> Result<Vec<serde_json::Value>, DecryptError> {
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
mod tests {
    use crate::e3client::{mock::MockE3TestClient, E3Payload};

    use super::*;
    use hyper::{header::HeaderValue, Body, Response};
    use shared::logging::RequestType;
    use tower::{service_fn, ServiceExt};

    #[tokio::test]
    async fn test_decrypt_service() {
        let mut e3_test_client = MockE3TestClient::new();
        let response_payload = CryptoRequest::new(Value::Null, Some(Value::Null));
        let response_payload2 = CryptoRequest::new(Value::Null, Some(Value::Null));

        // let con = Ok(CryptoRequest::new(Value::Null, Some(Value::Null))); 
        // e3_test_client
        //     .expect_decrypt_with_retries()
        //     .return_const(*&con);

        e3_test_client
            .expect_decrypt_with_retries()
            .returning(move |_, _: CryptoRequest| Ok(response_payload2.clone()));

        e3_test_client
            .expect_decrypt()
            .returning(move |_: CryptoRequest| Ok(response_payload.clone()));


        let echo_service = service_fn(|req: Request<Body>| async {
            let (parts, body) = req.into_parts();
            let body = hyper::body::to_bytes(body).await?;
            Ok::<_, hyper::Error>(Response::new(Body::from(body)))
        });

        let mut service = DecryptService {
            e3_client: Arc::new(e3_test_client),
            inner: echo_service,
        };
        let mut trx_ctx = TrxContextBuilder::init_trx_context_with_enclave_details(
            "uuid",
            "name",
            "team_uuid",
            "app_uuid",
            RequestType::HTTP,
        );
        let mut headers = hyper::HeaderMap::new();
        headers.append("Test", HeaderValue::from_str("ev:encrypted").unwrap());
        let mut request = Request::new(Body::from("Hello, World!"));
        request.extensions_mut().insert(trx_ctx);
        request.headers_mut().extend(headers);
        let response = service.call(request).await.unwrap();
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();

        assert_eq!(&body_bytes[..], b"Hello, World!");
    }
}
