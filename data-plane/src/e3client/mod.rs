mod tls_verifier;

use hyper::header::HeaderValue;
use hyper::{Body, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;

type E3Error = ClientError;

#[derive(Clone)]
pub struct E3Client {
    base_client: BaseClient,
}

impl std::default::Default for E3Client {
    fn default() -> Self {
        Self::new()
    }
}

use crate::base_tls_client::tls_client_config::get_tls_client_config;
use crate::base_tls_client::{AuthType, BaseClient, ClientError};
use crate::configuration;

impl E3Client {
    pub fn new() -> Self {
        let verifier = std::sync::Arc::new(tls_verifier::E3CertVerifier);
        let tls_connector =
            TlsConnector::from(std::sync::Arc::new(get_tls_client_config(verifier)));

        let server_name = ServerName::try_from(configuration::get_e3_host().as_str())
            .expect("Hardcoded hostname");

        Self {
            base_client: BaseClient::new(tls_connector, server_name, shared::ENCLAVE_CRYPTO_PORT),
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

    pub async fn decrypt<T, P: E3Payload>(
        &self,
        e3_auth_token: &HeaderValue,
        payload: P,
    ) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
    {
        let response = self
            .base_client
            .send(
                Some(AuthType::AttestationDoc(e3_auth_token.clone())),
                "POST",
                &self.uri("/decrypt"),
                payload.try_into_body()?,
            )
            .await?;
        self.parse_response(response).await
    }

    pub async fn encrypt<T, P: E3Payload>(
        &self,
        e3_auth_token: &HeaderValue,
        payload: P,
    ) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
    {
        let response = self
            .base_client
            .send(
                Some(AuthType::AttestationDoc(e3_auth_token.clone())),
                "POST",
                &self.uri("/encrypt"),
                payload.try_into_body()?,
            )
            .await?;
        self.parse_response(response).await
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
            )
            .await?;
        println!("{response:?}");
        Ok(response.status().is_success())
    }

    async fn parse_response<T: DeserializeOwned>(&self, res: Response<Body>) -> Result<T, E3Error> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body).await?;
        Ok(serde_json::from_slice(&response_body)?)
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
    team_uuid: String,
    app_uuid: String,
    data: Vec<EncryptedDataEntry>,
}

impl E3Payload for DecryptRequest {}

impl DecryptRequest {
    pub fn data(&self) -> &Vec<EncryptedDataEntry> {
        &self.data
    }
}

impl std::convert::From<(Vec<EncryptedDataEntry>, &crate::CageContext)> for DecryptRequest {
    fn from((val, context): (Vec<EncryptedDataEntry>, &crate::CageContext)) -> Self {
        Self {
            data: val,
            team_uuid: context.team_uuid().to_string(),
            app_uuid: context.app_uuid().to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CryptoRequest {
    pub team_uuid: String,
    pub app_uuid: String,
    pub data: Value,
}

impl E3Payload for CryptoRequest {}
impl CryptoRequest {
    pub fn data(&self) -> &Value {
        &self.data
    }
}

impl std::convert::From<(Value, &crate::CageContext)> for CryptoRequest {
    fn from((val, context): (Value, &crate::CageContext)) -> Self {
        Self {
            data: val,
            team_uuid: context.team_uuid().to_string(),
            app_uuid: context.app_uuid().to_string(),
        }
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
