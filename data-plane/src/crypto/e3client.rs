use hyper::header::HeaderValue;
use hyper::{Body, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use thiserror::Error;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;

use crate::base_tls_client::tls_client_config::get_tls_client_config;
use crate::base_tls_client::{AuthType, BaseClient, BaseClientError, OpenServerCertVerifier};
use crate::configuration;
use crate::crypto::token::TokenClient;
use crate::stats_client::StatsClient;

#[derive(Clone, Debug, Deserialize)]
pub struct E3ErrorDetails {
    message: String,
}

impl E3ErrorDetails {
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Error)]
pub enum E3Error {
    #[error(transparent)]
    ClientError(#[from] BaseClientError),
    #[error("Failed to obtain token to call E3 - {0}")]
    TokenClientError(#[from] TokenError),
    #[error("Request to E3 failed with status code {code} - {}", .details.message)]
    E3Error { details: E3ErrorDetails, code: u16 },
}

use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use super::token::TokenError;

#[derive(Clone)]
pub struct E3Client {
    base_client: BaseClient,
    token_client: TokenClient,
}

impl std::default::Default for E3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Client {
    pub fn new() -> Self {
        let verifier = std::sync::Arc::new(OpenServerCertVerifier);
        let tls_connector =
            TlsConnector::from(std::sync::Arc::new(get_tls_client_config(verifier)));

        let server_name = ServerName::try_from(configuration::get_e3_host().as_str())
            .expect("Hardcoded hostname");

        Self {
            base_client: BaseClient::new(tls_connector, server_name, shared::ENCLAVE_CRYPTO_PORT),
            token_client: TokenClient::new(),
        }
    }

    fn uri(&self, path: &str) -> String {
        format!(
            "https://{}:{}{}",
            configuration::get_e3_host(),
            shared::ENCLAVE_CRYPTO_PORT,
            path
        )
    }

    pub async fn decrypt<T, P: E3Payload>(&self, payload: P) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
    {
        let token = self.token_client.get_token().await?;
        let response = self
            .base_client
            .send(
                Some(AuthType::AttestationDoc(token)),
                "POST",
                &self.uri("/decrypt"),
                payload.try_into_body()?,
                None,
            )
            .await?;
        StatsClient::record_decrypt();
        self.parse_response(response).await
    }

    pub async fn decrypt_with_retries<T, P: E3Payload>(
        &self,
        retries: usize,
        payload: P,
    ) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        P: Clone,
    {
        let retry_strategy = ExponentialBackoff::from_millis(10)
            .map(jitter)
            .take(retries);

        Retry::spawn(retry_strategy, || async {
            self.decrypt(payload.clone()).await.map_err(|e| {
                log::error!("Error attempting decryption {e:?}");
                e
            })
        })
        .await
    }

    pub async fn encrypt<T, P: E3Payload>(
        &self,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
    {
        let request_headers = data_role
            .as_ref()
            .and_then(|role| hyper::header::HeaderValue::from_str(role).ok())
            .map(|role| {
                let mut header_map = hyper::HeaderMap::new();
                header_map.insert("x-evervault-data-role", role);
                header_map
            });
        let token = self.token_client.get_token().await?;
        let response = self
            .base_client
            .send(
                Some(AuthType::AttestationDoc(token)),
                "POST",
                &self.uri("/encrypt"),
                payload.try_into_body()?,
                request_headers,
            )
            .await?;
        StatsClient::record_encrypt();
        self.parse_response(response).await
    }

    pub async fn encrypt_with_retries<T, P>(
        &self,
        retries: usize,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        P: Clone + E3Payload,
    {
        let retry_strategy = ExponentialBackoff::from_millis(10)
            .map(jitter)
            .take(retries);

        Retry::spawn(retry_strategy, || async {
            self.encrypt(payload.clone(), data_role.clone()).await
        })
        .await
    }

    pub async fn authenticate(
        &self,
        api_key: &HeaderValue,
        payload: AuthRequest,
    ) -> Result<bool, E3Error> {
        let response = self
            .base_client
            .send(
                Some(AuthType::ApiKey(api_key.clone())),
                "POST",
                &self.uri("/authenticate"),
                payload.try_into_body()?,
                None,
            )
            .await?;
        log::debug!("{response:?}");
        if response.status().is_success() {
            Ok(true)
        } else {
            let status_code = response.status().as_u16();
            let response_body = hyper::body::to_bytes(response)
                .await
                .map_err(BaseClientError::from)?;
            let auth_error_details: E3ErrorDetails =
                serde_json::from_slice(&response_body).map_err(BaseClientError::from)?;
            Err(E3Error::E3Error {
                details: auth_error_details,
                code: status_code,
            })
        }
    }

    async fn parse_response<T: DeserializeOwned>(&self, res: Response<Body>) -> Result<T, E3Error> {
        let (res_info, body) = res.into_parts();
        let response_body = hyper::body::to_bytes(body)
            .await
            .map_err(BaseClientError::from)?;
        if res_info.status.is_success() {
            Ok(serde_json::from_slice(&response_body).map_err(BaseClientError::from)?)
        } else {
            let error_details: E3ErrorDetails =
                serde_json::from_slice(&response_body).map_err(BaseClientError::from)?;
            Err(E3Error::E3Error {
                details: error_details,
                code: res_info.status.as_u16(),
            })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub team_uuid: String,
    pub app_uuid: String,
    pub cage_uuid: Option<String>,
}

impl E3Payload for AuthRequest {}

impl std::convert::From<&crate::CageContext> for AuthRequest {
    fn from(context: &crate::CageContext) -> Self {
        Self {
            team_uuid: context.team_uuid().to_string(),
            app_uuid: context.app_uuid().to_string(),
            cage_uuid: Some(context.cage_uuid().to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDataEntry {
    range: (usize, usize),
    value: Value,
}

impl EncryptedDataEntry {
    pub fn range(&self) -> (usize, usize) {
        self.range
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn new(range: (usize, usize), value: Value) -> Self {
        Self { range, value }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    data: Vec<EncryptedDataEntry>,
}

impl E3Payload for DecryptRequest {}

impl DecryptRequest {
    pub fn data(&self) -> &Vec<EncryptedDataEntry> {
        &self.data
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoRequest {
    pub data: Value,
}

impl CryptoRequest {
    pub fn new(data: Value) -> CryptoRequest {
        CryptoRequest { data }
    }
}

impl E3Payload for CryptoRequest {}
impl CryptoRequest {
    pub fn data(&self) -> &Value {
        &self.data
    }
    pub fn to_vec(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

pub trait E3Payload: Sized + Serialize {
    fn try_into_body(self) -> Result<hyper::Body, E3Error> {
        Ok(hyper::Body::from(
            serde_json::to_vec(&self).map_err(BaseClientError::from)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
pub struct CryptoResponse {
    pub data: Value,
}
