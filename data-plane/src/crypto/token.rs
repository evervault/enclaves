use crate::cache::E3_TOKEN;
use crate::config_client::{ConfigClient, ConfigClientError};
#[cfg(feature = "enclave")]
use crate::crypto::attest::AttestationError;
use cached::Cached;
use hyper::header::InvalidHeaderValue;
use hyper::http::HeaderValue;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "enclave")]
    #[error("Attestation error - {0:?}")]
    AttestationError(#[from] AttestationError),
    #[error("Invalid header value - {0:?}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error(transparent)]
    ConfigClient(#[from] ConfigClientError),
}

#[derive(Clone, Debug)]
pub struct AttestationAuth {
    pub token: HeaderValue,
    pub doc: HeaderValue,
}

#[derive(Clone)]
pub struct TokenClient {
    config: ConfigClient,
}

impl Default for TokenClient {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenClient {
    pub fn new() -> Self {
        TokenClient {
            config: ConfigClient::new(),
        }
    }

    pub async fn get_token(&self) -> Result<AttestationAuth, TokenError> {
        let token_key: String = "e3_token".to_string();
        let mut cache = E3_TOKEN.lock().await;
        let auth = match cache.cache_get(&token_key) {
            Some(token) => token.clone(),
            None => {
                let response = self.config.get_e3_token().await?;
                let doc = Self::get_attestation_doc_token(response.token_id().into_bytes())?;
                let token_header = hyper::http::header::HeaderValue::from_str(&response.token())?;
                let attestation_header = hyper::http::header::HeaderValue::from_str(&doc)?;
                let token = AttestationAuth {
                    token: token_header,
                    doc: attestation_header,
                };
                cache.cache_set(token_key, token.clone());
                token
            }
        };
        Ok(auth)
    }

    #[cfg(feature = "enclave")]
    fn get_attestation_doc_token(nonce: Vec<u8>) -> Result<String, TokenError> {
        use crate::crypto::attest;
        use openssl::base64::encode_block;

        let attestation_doc = attest::get_attestation_doc(None, Some(nonce))?;
        Ok(encode_block(&attestation_doc))
    }

    #[cfg(not(feature = "enclave"))]
    fn get_attestation_doc_token(_: Vec<u8>) -> Result<String, TokenError> {
        Ok("local-attestation-token".to_string())
    }
}
