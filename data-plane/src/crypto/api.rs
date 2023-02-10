use bytes::Bytes;
use cached::{Cached, TimedSizedCache};
use hyper::http::HeaderValue;
use hyper::{self, Body};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::{self};
use sha2::{Digest, Sha256};
use shared::server::config_server::routes::ConfigServerPath;
use shared::server::error::ServerResult;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use thiserror::Error;

use hyper::{
    service::{make_service_fn, service_fn},
    Method, Request, Response, Server,
};

use crate::base_tls_client::ClientError;
use crate::config_client::ConfigClient;
use crate::e3client::{CryptoRequest, CryptoResponse, E3Client};
use crate::error::Error;
use crate::{CageContext, CageContextError};

#[cfg(feature = "enclave")]
use super::attest;

pub struct CryptoApi {
    e3_client: E3Client,
    cache: TimedSizedCache<String, String>,
    config_client: ConfigClient,
}

impl Default for CryptoApi {
    fn default() -> Self {
        Self::new()
    }
}

const CACHE_ITEM_LIFETIME: u64 = 280;

#[derive(Debug, Error)]
pub enum CryptoApiError {
    #[error("Missing API key")]
    MissingApiKey,
    #[error("Missing cage context — {0:?}")]
    MissingCageContext(#[from] std::env::VarError),
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
    #[error("Couldn't get cage context")]
    CageContextError(#[from] CageContextError),
    #[error("Error — {0:?}")]
    Error(#[from] Error),
}

impl From<CryptoApiError> for hyper::Response<hyper::Body> {
    fn from(err: CryptoApiError) -> Self {
        match err {
            CryptoApiError::MissingApiKey => build_response(401, Body::from(err.to_string())),
            CryptoApiError::SerdeError(error) => build_response(400, Body::from(error.to_string())),
            CryptoApiError::SerializationError => build_response(400, Body::from(err.to_string())),
            _ => build_response(500, Body::from(err.to_string())),
        }
    }
}

fn build_response(status: u16, body: Body) -> hyper::Response<hyper::Body> {
    hyper::Response::builder()
        .status(status)
        .body(body)
        .expect("Failed to build response")
}

impl CryptoApi {
    pub fn new() -> Self {
        Self {
            e3_client: E3Client::new(),
            cache: TimedSizedCache::with_size_and_lifespan(1, CACHE_ITEM_LIFETIME),
            config_client: ConfigClient::new(),
        }
    }

    pub async fn listen() -> ServerResult<()> {
        println!("Crypto API started");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);

        let service = make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(|req| Self::api(CryptoApi::new(), req)))
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

    async fn get_token(&mut self, body: Bytes) -> Result<String, CryptoApiError> {
        let token_key: String = "e3_token".to_string();
        let token = match self.cache.cache_get(&token_key) {
            Some(token) => token.clone(),
            None => {
                let token = self
                    .config_client
                    .get_token(ConfigServerPath::GetE3Token)
                    .await?
                    .token();
                self.cache.cache_set(token_key, token.clone());
                token
            }
        };

        let mut sha256 = Sha256::new();
        sha256.update(body);
        let payload_digest = sha256.finalize();

        Self::get_attestation_doc_token(token, payload_digest.to_vec())
    }

    #[cfg(feature = "enclave")]
    fn get_attestation_doc_token(token: String, nonce: Vec<u8>) -> Result<String, CryptoApiError> {
        use openssl::base64::encode_block;

        let attestation_doc =
            attest::get_attestation_doc(Some(token.as_bytes().to_vec()), Some(nonce))?;
        Ok(encode_block(&attestation_doc))
    }

    #[cfg(not(feature = "enclave"))]
    fn get_attestation_doc_token(_: String, _: Vec<u8>) -> Result<String, CryptoApiError> {
        Ok("local-attestation-token".to_string())
    }

    async fn build_request(
        token: String,
        bytes: Bytes,
    ) -> Result<(HeaderValue, CryptoRequest), CryptoApiError> {
        let cage_context = CageContext::get()?;
        let api_key = hyper::http::header::HeaderValue::from_str(&token).unwrap();
        let body: Value =
            serde_json::from_slice(&bytes).map_err(|_| CryptoApiError::SerializationError)?;
        let payload = CryptoRequest::from((body, &cage_context));
        Ok((api_key, payload))
    }

    async fn encrypt(&mut self, req: Request<Body>) -> Result<Body, CryptoApiError> {
        let (token, body) = self.get_token_and_body(req).await?;
        let (api_key, payload) = Self::build_request(token.clone(), body).await?;
        let e3_response: CryptoResponse = self.e3_client.encrypt(&api_key, payload).await?;
        Ok(hyper::Body::from(serde_json::to_vec(&e3_response.data)?))
    }

    async fn decrypt(&mut self, req: Request<Body>) -> Result<Body, CryptoApiError> {
        let (token, body) = self.get_token_and_body(req).await?;
        let (api_key, payload) = Self::build_request(token, body).await?;
        let e3_response: CryptoResponse = self.e3_client.decrypt(&api_key, payload).await?;
        Ok(hyper::Body::from(serde_json::to_vec(&e3_response.data)?))
    }

    async fn get_token_and_body(
        &mut self,
        req: Request<Body>,
    ) -> Result<(String, Bytes), CryptoApiError> {
        let (_, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await?;
        let token = self.get_token(body_bytes.clone()).await?;
        Ok((token, body_bytes))
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
    async fn get_attestation_doc(self, req: Request<Body>) -> Result<Body, CryptoApiError> {
        use hyper::Client;

        let client = Client::new();
        let request = Request::builder()
            .uri("http://127.0.0.1:7677/attestation-doc")
            .method("POST")
            .body(req.into_body())
            .expect("Couldnt build request");
        let resp = client.request(request).await?;
        Ok(resp.into_body())
    }
}

#[derive(Deserialize, Serialize)]
pub struct AttestationRequest {
    nonce: Option<String>,
    challenge: Option<String>,
}
