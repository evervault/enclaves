use hyper::{self, Body};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::{self};
use shared::server::error::ServerResult;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;

use hyper::{
    service::{make_service_fn, service_fn},
    Method, Request, Response, Server,
};

use crate::base_tls_client::ClientError;
use crate::e3client::{CryptoRequest, CryptoResponse, E3Api, E3Client};
use crate::error::Error;
use crate::health::agent::{Diagnostic, DiagnosticSender};
use crate::ContextError;

#[cfg(feature = "enclave")]
use super::attest;

#[derive(Clone)]
pub struct CryptoApi {
    e3_client: E3Client,
}

#[derive(Debug, Error)]
pub enum CryptoApiError {
    #[error("Missing enclave context — {0:?}")]
    MissingEnclaveContext(#[from] std::env::VarError),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Hyper Error — {0:?}")]
    HyperError(#[from] hyper::Error),
    #[error("Client Error — {0:?}")]
    ClientError(#[from] ClientError),
    #[cfg(feature = "enclave")]
    #[error("Attestation Error — {0:?}")]
    #[cfg(feature = "enclave")]
    Attestation(#[from] attest::AttestationError),
    #[error("Not Found")]
    NotFound,
    #[error("Could not deserialize your payload")]
    SerializationError,
    #[error("Failed to read context - {0}")]
    ContextError(#[from] ContextError),
    #[error("Error — {0:?}")]
    Error(#[from] Error),
}

impl From<CryptoApiError> for hyper::Response<hyper::Body> {
    fn from(err: CryptoApiError) -> Self {
        match err {
            CryptoApiError::SerdeError(error) => build_response(400, error.to_string()),
            CryptoApiError::SerializationError => build_response(400, err.to_string()),
            _ => build_response(500, err.to_string()),
        }
    }
}

fn build_response(status: u16, body: String) -> hyper::Response<hyper::Body> {
    hyper::Response::builder()
        .status(status)
        .header("content-length", body.len())
        .body(body.into())
        .expect("Failed to build response")
}

impl CryptoApi {
    pub fn new(hc_sender: DiagnosticSender) -> Self {
        Self {
            e3_client: E3Client::new(Some(hc_sender)),
        }
    }

    pub async fn listen(hc_sender: DiagnosticSender) -> ServerResult<()> {
        log::info!("Crypto API started");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);

        let service = make_service_fn(move |_| {
            let hc_sender = Arc::clone(&hc_sender);

            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    Self::api(CryptoApi::new(Arc::clone(&hc_sender)), req)
                }))
            }
        });
        let _ = Server::bind(&addr).serve(service).await;

        #[allow(unreachable_code)]
        Ok(())
    }

    async fn api(
        mut self,
        req: Request<Body>,
    ) -> Result<hyper::Response<hyper::Body>, CryptoApiError> {
        let response = match (req.method(), req.uri().path()) {
            (&Method::POST, "/encrypt") => self.encrypt(req).await,
            (&Method::POST, "/decrypt") => self.decrypt(req).await,
            (&Method::POST, "/attestation-doc") => self.get_attestation_doc(req).await,
            _ => Err(CryptoApiError::NotFound),
        };

        match response {
            Ok(body) => Ok(Response::builder()
                .body(body)
                .expect("Failed to build response")),
            Err(error) => Ok(error.into()),
        }
    }

    async fn build_request(&mut self, req: Request<Body>) -> Result<CryptoRequest, CryptoApiError> {
        let (_, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await?;
        let body: Value =
            serde_json::from_slice(&body_bytes).map_err(|_| CryptoApiError::SerializationError)?;
        let payload = CryptoRequest::new(body);
        Ok(payload)
    }

    async fn encrypt(&mut self, req: Request<Body>) -> Result<Body, CryptoApiError> {
        let data_role = req
            .headers()
            .get("x-evervault-data-role")
            .and_then(|role| role.to_str().ok())
            .map(|role_str| role_str.to_string());
        let request = self.build_request(req).await?;
        let e3_response: CryptoResponse = self
            .e3_client
            .encrypt_with_retries(2, request, data_role)
            .await?;
        Ok(hyper::Body::from(serde_json::to_vec(&e3_response.data)?))
    }

    async fn decrypt(&mut self, req: Request<Body>) -> Result<Body, CryptoApiError> {
        let request = self.build_request(req).await?;
        let e3_response: CryptoResponse = self.e3_client.decrypt_with_retries(2, request).await?;
        Ok(hyper::Body::from(serde_json::to_vec(&e3_response.data)?))
    }

    #[cfg(feature = "enclave")]
    async fn get_attestation_doc(self, mut req: Request<Body>) -> Result<Body, CryptoApiError> {
        use hyper::body;

        let body = req.body_mut();
        let bytes = body::to_bytes(body).await?;
        let body: Value = serde_json::from_slice(&bytes)?;
        let ad_request: AttestationRequest = serde_json::from_value(body)?;
        let challenge = ad_request.challenge.map(|chal| chal.as_bytes().to_vec());
        let nonce = ad_request.nonce.map(|non| non.as_bytes().to_vec());
        let doc = attest::get_attestation_doc(challenge, nonce)?;
        Ok(Body::from(doc))
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_attestation_doc(self, _: Request<Body>) -> Result<Body, CryptoApiError> {
        #[derive(Serialize, Deserialize, Debug)]
        struct TestData {
            pcr0: String,
            pcr1: String,
            pcr2: String,
            pcr8: String,
        }
        let test = TestData {
            pcr0: "000".to_string(),
            pcr1: "000".to_string(),
            pcr2: "000".to_string(),
            pcr8: "000".to_string(),
        };
        let res: Vec<u8> = serde_cbor::to_vec(&test).unwrap();

        Ok(Body::from(res))
    }
}

#[derive(Deserialize, Serialize)]
pub struct AttestationRequest {
    nonce: Option<String>,
    challenge: Option<String>,
}
