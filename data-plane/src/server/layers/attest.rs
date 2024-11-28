use cached::Cached;
use hyper::http::{Request, Response};
use hyper::Body;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use tower::{Layer, Service};

use crate::cache::ATTESTATION_DOC;
use crate::crypto::attest;
use crate::server::http::build_internal_error_response;
use crate::server::tls::TRUSTED_PUB_CERT;

#[derive(Clone)]
pub struct AttestLayer;

impl<S> Layer<S> for AttestLayer {
    type Service = AttestService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AttestService { inner }
    }
}

#[derive(Serialize, Deserialize)]
struct AttestationResponse {
    attestation_doc: String,
}

#[derive(Clone)]
pub struct AttestService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for AttestService<S>
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
        // skip straight to inner if request is not for attestation path
        if !is_attestation_request(&req) {
            let clone = self.inner.clone();
            let mut inner = std::mem::replace(&mut self.inner, clone);
            return Box::pin(inner.call(req));
        }

        Box::pin(async move {
            let attestation_doc_key: String = "attestation_doc".to_string();
            let mut cache = ATTESTATION_DOC.lock().await;

            let base64_doc = match cache.cache_get(&attestation_doc_key) {
                Some(ad) => ad.clone(),
                None => {
                    let challenge = TRUSTED_PUB_CERT.get();
                    let doc = match attest::get_attestation_doc(challenge.cloned(), None) {
                        Ok(ad) => ad,
                        Err(e) => {
                            log::error!("Failed to generate attestation doc. Error: {:?}", e);
                            return Ok(build_internal_error_response(None));
                        }
                    };
                    let base64_doc = base64::encode(doc);
                    cache.cache_set(attestation_doc_key, base64_doc.clone());
                    log::info!("Attestation doc generated and cached.");
                    base64_doc
                }
            };

            let response = AttestationResponse {
                attestation_doc: base64_doc,
            };

            let response_payload = serde_json::to_string(&response).expect("Infallible");
            let attestation_response = Response::builder()
                .status(200)
                .header(hyper::http::header::CONTENT_TYPE, "application/json")
                .header(hyper::http::header::CONTENT_LENGTH, response_payload.len())
                .body(Body::from(response_payload))
                .unwrap_or_else(|e| build_internal_error_response(Some(e.to_string())));

            Ok(attestation_response)
        })
    }
}

fn is_attestation_request(req: &Request<Body>) -> bool {
    req.uri().path() == "/.well-known/attestation"
}

#[cfg(test)]
mod test {
    use hyper::Body;

    use super::is_attestation_request;

    #[test]
    fn correctly_identifies_attestation_requests() {
        let req = hyper::Request::builder()
            .uri("http://localhost:1234/.well-known/attestation")
            .body(Body::empty())
            .unwrap();
        assert!(is_attestation_request(&req));
    }

    #[test]
    fn correctly_identifies_non_attestation_requests() {
        let req = hyper::Request::builder()
            .uri("http://localhost:1234/echo")
            .body(Body::empty())
            .unwrap();
        assert!(!is_attestation_request(&req));
    }
}
