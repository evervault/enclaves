use hyper::http::{Request, Response};
use hyper::Body;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use tower::{Layer, Service};

use crate::crypto::attest;
use crate::server::error::TlsError as Error;
use crate::server::tls::TRUSTED_PUB_CERT;

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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    // Service is always ready to receive requests
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // skip straight to inner if request is not for attestation path
        if req.uri() != "/.well-known/attestation" {
            let clone = self.inner.clone();
            let mut inner = std::mem::replace(&mut self.inner, clone);
            return Box::pin(inner.call(req));
        }

        Box::pin(async move {
            let challenge = TRUSTED_PUB_CERT.get();

            let attestation_doc = match attest::get_attestation_doc(challenge.cloned(), None) {
                Ok(attestation_doc) => attestation_doc,
                Err(e) => return Ok(e.into()),
            };

            let base64_doc = base64::encode(attestation_doc);

            let response = AttestationResponse {
                attestation_doc: base64_doc,
            };

            let attestation_response = Response::builder()
                .status(200)
                .body(Body::from(
                    serde_json::to_string(&response).expect("Infallible"),
                ))
                .unwrap();

            return Ok(attestation_response);
        })
    }
}
