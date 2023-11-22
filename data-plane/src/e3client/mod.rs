use async_trait::async_trait;
use hyper::header::HeaderValue;
use hyper::{Body, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use std::ops::Deref;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;

type E3Error = ClientError;

use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

#[cfg(test)]
pub mod mock;

#[async_trait]
pub trait E3Api {
    async fn decrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(
        &self,
        payload: P,
    ) -> Result<T, E3Error>;

    async fn encrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(
        &self,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error>;

    async fn authenticate(
        &self,
        api_key: &HeaderValue,
        payload: AuthRequest,
    ) -> Result<(), E3Error>;

    async fn decrypt_with_retries<
        T: DeserializeOwned + 'static,
        P: E3Payload + Clone + Send + Sync + 'static,
    >(
        &self,
        retries: usize,
        payload: P,
    ) -> Result<T, E3Error> {
        let retry_strategy = ExponentialBackoff::from_millis(10)
            .map(jitter)
            .take(retries);

        Retry::spawn(retry_strategy, || {
            let owned_payload = payload.clone();
            async {
                self.decrypt(owned_payload).await.map_err(|e| {
                    log::error!("Error attempting decryption {e:?}");
                    e
                })
            }
        })
        .await
    }

    async fn encrypt_with_retries<
        T: DeserializeOwned + 'static,
        P: E3Payload + Clone + Send + Sync + 'static,
    >(
        &self,
        retries: usize,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error> {
        let retry_strategy = ExponentialBackoff::from_millis(10)
            .map(jitter)
            .take(retries);

        Retry::spawn(retry_strategy, || {
            let owned_payload = payload.clone();
            let owned_role = data_role.clone();
            async move { self.encrypt(owned_payload, owned_role).await }
        })
        .await
    }
}

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

use crate::base_tls_client::tls_client_config::get_tls_client_config;
use crate::base_tls_client::{AuthType, BaseClient, ClientError, OpenServerCertVerifier};
use crate::configuration;
use crate::crypto::token::TokenClient;
use crate::stats_client::StatsClient;

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

    async fn parse_response<T: DeserializeOwned>(&self, res: Response<Body>) -> Result<T, E3Error> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body).await?;
        Ok(serde_json::from_slice(&response_body)?)
    }
}

#[async_trait]
impl E3Api for E3Client {
    async fn decrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(
        &self,
        payload: P,
    ) -> Result<T, E3Error> {
        let token = self
            .token_client
            .get_token()
            .await
            .map_err(|e| E3Error::General(format!("Couldn't get E3 token {e}")))?;
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

    async fn encrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(
        &self,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error> {
        let request_headers = data_role
            .as_ref()
            .and_then(|role| hyper::header::HeaderValue::from_str(role).ok())
            .map(|role| {
                let mut header_map = hyper::HeaderMap::new();
                header_map.insert("x-evervault-data-role", role);
                header_map
            });
        let token = self
            .token_client
            .get_token()
            .await
            .map_err(|e| E3Error::General(format!("Couldn't get E3 token {e}")))?;
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

    async fn authenticate(
        &self,
        api_key: &HeaderValue,
        payload: AuthRequest,
    ) -> Result<(), E3Error> {
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
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthRequest {
    pub team_uuid: String,
    pub app_uuid: String,
    pub cage_uuid: Option<String>,
}

impl E3Payload for AuthRequest {}

impl<C: Deref<Target = crate::CageContext>> std::convert::From<C> for AuthRequest {
    fn from(context: C) -> Self {
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
        Ok(hyper::Body::from(serde_json::to_vec(&self)?))
    }
}

#[derive(Serialize, Deserialize)]
pub struct CryptoResponse {
    pub data: Value,
}
