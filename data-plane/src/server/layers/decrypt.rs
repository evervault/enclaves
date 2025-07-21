use futures::StreamExt;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::http::{Request, Response};
use hyper::Body;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tower::{Layer, Service};

use crate::base_tls_client::ClientError;
use crate::e3client::EncryptedDataEntry;
use crate::e3client::EncryptedHeader;
use crate::e3client::{AutoDecryptRequest, E3Api};
use shared::logging::TrxContextBuilder;

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

lazy_static! {
    static ref CIPHERTEXT_VERSION_REGEX: regex::Regex = get_ciphertext_regex();
}

#[derive(Clone)]
pub struct DecryptLayer<T: E3Api> {
    e3_client: Arc<T>,
}

impl<T: E3Api> DecryptLayer<T> {
    pub fn new(e3_client: Arc<T>) -> Self {
        Self { e3_client }
    }
}

impl<S, T: E3Api> Layer<S> for DecryptLayer<T> {
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
            let encrypted_headers: Vec<EncryptedHeader> = req_info
                .headers
                .clone()
                .into_iter()
                .filter_map(|(header_name, header_value)| {
                    let header_val = header_value.to_str().ok()?;
                    if CIPHERTEXT_VERSION_REGEX.is_match(header_val) {
                        Some(EncryptedHeader::new(
                            header_name?.to_string(),
                            header_val.to_string(),
                        ))
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
                let request_payload =
                    AutoDecryptRequest::new(decryption_payload, encrypted_headers);
                let decrypted: AutoDecryptRequest =
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
                decrypted.header_data().iter().for_each(|header| {
                    let key_result = HeaderName::try_from(header.key().clone());
                    let value_result = HeaderValue::from_str(header.value());

                    match (key_result, value_result) {
                        (Ok(key), Ok(value)) => {
                            req_info.headers.insert(key, value);
                        }
                        (Err(e), _) => {
                            eprintln!("Failed to parse header key: {e:?}");
                        }
                        (_, Err(e)) => {
                            eprintln!("Failed to parse header value: {e:?}");
                        }
                    }
                });
            }

            let mut decrypted_request = hyper::Request::from_parts(req_info, Body::from(bytes_vec));
            context.n_decrypted_fields(n_decrypts);
            decrypted_request.extensions_mut().insert(context);
            inner.call(decrypted_request).await
        })
    }
}

fn inject_decrypted_values_into_request_vec(
    decrypted_values: &AutoDecryptRequest,
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
) -> Result<Vec<EncryptedDataEntry>, DecryptError> {
    let mut stream_reader =
        crate::crypto::stream::IncomingStreamDecoder::create_reader(incoming_payload);

    let mut decryption_payload = vec![];
    while let Some(parsed_frame) = stream_reader.next().await {
        let (range, ciphertext) = match parsed_frame? {
            crate::crypto::stream::IncomingFrame::Ciphertext(ciphertext) => ciphertext,
            _ => continue,
        };

        let encrypted_data = EncryptedDataEntry::new(range, Value::from(ciphertext.to_string()));
        decryption_payload.push(encrypted_data);
    }
    Ok(decryption_payload)
}

fn get_ciphertext_regex() -> regex::Regex {
    let pattern = r"^ev\:(RFVC|T1JL|Tk9D|TENZ|QlJV|QkTC|S0lS|[a-zA-Z0-9]{16})\:.*";
    Regex::new(pattern).expect("Failed to create regex")
}

#[cfg(test)]
mod tests {
    use crate::e3client::{mock::MockE3TestClient, EncryptedHeader};

    use super::*;
    use hyper::body::to_bytes;
    use hyper::{header::HeaderValue, Body, Response};
    use serde_json::json;
    use serde_json::Value;
    use shared::logging::RequestType;
    use shared::logging::TrxContextBuilder;
    use tower::service_fn;

    #[tokio::test]
    async fn test_decrypt_body() {
        let mut e3_test_client = MockE3TestClient::new();
        let response_payload = AutoDecryptRequest::new(
            vec![EncryptedDataEntry::new(
                (8, 116),
                Value::String("plaintext".to_string()),
            )],
            vec![],
        );
        let encrypted_header_key = "Test";

        e3_test_client
            .expect_decrypt_with_retries::<AutoDecryptRequest, AutoDecryptRequest>()
            .times(1)
            .returning(move |_, _: AutoDecryptRequest| Ok(response_payload.clone()));

        let mock_service = service_fn(|req: Request<Body>| async {
            let (parts, body) = req.into_parts();
            let mut response = Response::new(body);
            parts.headers.iter().for_each(|(key, val)| {
                response.headers_mut().insert(key, val.clone());
            });

            Ok::<_, hyper::Error>(response)
        });

        let mut service = DecryptService {
            e3_client: Arc::new(e3_test_client),
            inner: mock_service,
        };

        let mut headers = hyper::HeaderMap::new();
        headers.append(
            encrypted_header_key,
            HeaderValue::from_str("ev:encrypted").unwrap(),
        );
        let mut request = Request::new(Body::from(
            json!({
                "test": "ev:Tk9D:string:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$"
            })
            .to_string(),
        ));

        request.extensions_mut().insert(get_test_trx());
        request.headers_mut().extend(headers);

        let response = service.call(request).await.unwrap();
        let (_, body) = response.into_parts();
        let bytes = to_bytes(body).await.unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json!({
                "test": "plaintext"
            }),
            json
        );
    }

    #[tokio::test]
    async fn test_decrypt_header() {
        let mut e3_test_client = MockE3TestClient::new();
        let response_payload = AutoDecryptRequest::new(
            vec![],
            vec![EncryptedHeader::new(
                "Test".to_string(),
                "plaintext".to_string(),
            )],
        );
        let encrypted_header_key = "Test";

        e3_test_client
            .expect_decrypt_with_retries::<AutoDecryptRequest, AutoDecryptRequest>()
            .times(1)
            .returning(move |_, _: AutoDecryptRequest| Ok(response_payload.clone()));

        let mock_service = service_fn(|req: Request<Body>| async {
            let (parts, body) = req.into_parts();
            let mut response = Response::new(body);
            parts.headers.iter().for_each(|(key, val)| {
                response.headers_mut().insert(key, val.clone());
            });

            Ok::<_, hyper::Error>(response)
        });

        let mut service = DecryptService {
            e3_client: Arc::new(e3_test_client),
            inner: mock_service,
        };

        let mut headers = hyper::HeaderMap::new();
        headers.append(
            encrypted_header_key,
            HeaderValue::from_str("ev:Tk9D:boolean:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$").unwrap(),
        );
        let mut request = Request::new(Body::empty());

        request.extensions_mut().insert(get_test_trx());
        request.headers_mut().extend(headers);

        let response = service.call(request).await.unwrap();
        let (parts, _) = response.into_parts();

        assert_eq!(
            parts.headers.get(encrypted_header_key).unwrap(),
            "plaintext"
        );
    }

    #[tokio::test]
    async fn test_noop_with_plaintext_header() {
        let mut e3_test_client = MockE3TestClient::new();
        let header_key = "Test";

        e3_test_client
            .expect_decrypt_with_retries::<AutoDecryptRequest, AutoDecryptRequest>()
            .times(0);

        let mock_service = service_fn(|req: Request<Body>| async {
            let (parts, body) = req.into_parts();
            let mut response = Response::new(body);
            parts.headers.iter().for_each(|(key, val)| {
                response.headers_mut().insert(key, val.clone());
            });

            Ok::<_, hyper::Error>(response)
        });

        let mut service = DecryptService {
            e3_client: Arc::new(e3_test_client),
            inner: mock_service,
        };

        let mut headers = hyper::HeaderMap::new();
        headers.append(header_key, HeaderValue::from_str("plaintext").unwrap());
        let mut request = Request::new(Body::from(
            json!({
                "test": "test"
            })
            .to_string(),
        ));

        request.extensions_mut().insert(get_test_trx());
        request.headers_mut().extend(headers);

        let response = service.call(request).await.unwrap();

        assert_eq!(
            response
                .headers()
                .get(header_key)
                .unwrap()
                .to_str()
                .unwrap(),
            "plaintext"
        );
    }

    #[tokio::test]
    async fn test_ciphertext_regex() {
        let regex = get_ciphertext_regex();
        assert!(regex.is_match("ev:RFVC:1234567890"));
        assert!(regex.is_match("ev:T1JL:1234567890"));
        assert!(regex.is_match("ev:QlJV:1234567890"));
        assert!(regex.is_match("ev:QkTC:1234567890"));
        assert!(regex.is_match("ev:S0lS:1234567890"));
        assert!(regex.is_match("ev:Tk9D:1234567890"));
        assert!(regex.is_match("ev:TENZ:1234567890"));
        assert!(regex.is_match("ev:9ESJyCXIkIS1hpMg:A7KyUHHg0VYFw7jDZUBQeMWUDA4EeMKKtQrivOG+meGy:5NsnpUnLrsWrM2ccX+r/pXtZ:$"));
        assert!(!regex.is_match("ev:INVALID:1234567890"));
    }

    fn get_test_trx() -> TrxContextBuilder {
        TrxContextBuilder::init_trx_context_with_enclave_details(
            "uuid",
            "name",
            "team_uuid",
            "app_uuid",
            RequestType::HTTP,
        )
        .uri(Some("test".to_string()))
        .request_method(Some("GET".to_string()))
        .clone()
    }
}
