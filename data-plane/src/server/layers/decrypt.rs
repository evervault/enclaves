use futures::StreamExt;
use hyper::header::InvalidHeaderValue;
use hyper::http::{HeaderValue, Request, Response};
use hyper::Body;
use sha2::Digest;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tower::{Layer, Service};

use crate::base_tls_client::ClientError;
use crate::{
    e3client::{AuthRequest, CryptoRequest, DecryptRequest, E3Client},
    CageContext,
};

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
            .header("content-length", msg.len())
            .body(body.into())
            .expect("Failed to build auth error to response")
    }
}

pub struct DecryptLayer {
    e3_client: Arc<E3Client>,
}

impl DecryptLayer {
    pub fn new(e3_client: Arc<E3Client>) -> Self {
        Self { e3_client }
    }
}

impl<S> Layer<S> for DecryptLayer {
    type Service = DecryptService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DecryptService {
            e3_client: self.e3_client.clone(),
            inner,
        }
    }
}

pub struct DecryptService<S> {
    e3_client: Arc<E3Client>,
    inner: S,
}

impl<S> Service<Request<Body>> for DecryptService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: 'static,
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

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let e3_client = self.e3_client.clone();
        Box::pin(async move {
            let (mut req_info, req_body) = req.into_parts();
            let request_bytes = match hyper::body::to_bytes(req_body).await {
                Ok(body_bytes) => body_bytes,
                Err(e) => {
                    log::error!("Failed to read entire body — {e}");
                    return Ok(DecryptError::FailedToSerializeRequest.into());
                }
            };

            let decryption_payload = match extract_ciphertexts_from_payload(&request_bytes).await {
                Ok(decryption_res) => decryption_res,
                Err(e) => {
                    log::error!(
                        "An error occurred while parsing the incoming stream for ciphertexts - {e}"
                    );
                    return Ok(e.into());
                }
            };

            let n_decrypts: Option<u32> = decryption_payload.len().try_into().ok();

            let mut bytes_vec = request_bytes.to_vec();
            if !decryption_payload.is_empty() {
                let request_payload =
                    CryptoRequest::new(serde_json::Value::Array(decryption_payload));
                let decrypted: DecryptRequest =
                    match e3_client.decrypt_with_retries(2, request_payload).await {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            log::error!("Failed to decrypt — {e}");
                            return Ok(DecryptError::from(e).into());
                        }
                    };

                log::info!("Decryption complete, rebuilding request");
                inject_decrypted_values_into_request_vec(&decrypted, &mut bytes_vec);
                req_info.headers.insert("content-length", bytes_vec.len());
            }
            let decrypted_request = hyper::Request::from_parts(req_info, Body::from(bytes_vec));
            inner.call(decrypted_request).await
        })
    }
}

fn inject_decrypted_values_into_request_vec(
    decrypted_values: &DecryptRequest,
    request_bytes: &mut Vec<u8>,
) {
    decrypted_values.data().iter().rev().for_each(|entry| {
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
