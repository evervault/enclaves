use async_trait::async_trait;
use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::http::StatusCode;
use hyper::{Body, Response};
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, DeleteObjectRequest, GetCertTokenResponseDataPlane,
    GetE3TokenResponseDataPlane, GetObjectRequest, GetObjectResponse, GetTokenRequestDataPlane,
    JwkResponse, JwsRequest, JwsResponse, PostTrxLogsRequest, PutObjectRequest, SignatureType,
};
use shared::server::config_server::routes::ConfigServerPath;
use thiserror::Error;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::base_tls_client::BaseClientError;
use crate::connection;

use connection::Connection;

#[derive(Debug, Error)]
pub enum ConfigClientError {
    #[error(transparent)]
    ClientError(#[from] BaseClientError),
    #[error("Request to config server failed with status code {code} - {message}")]
    FailedRequest { code: u16, message: String },
}

impl ConfigClientError {
    async fn from_response(res: hyper::Response<hyper::Body>) -> Self {
        let status_code = res.status().as_u16();
        let body_bytes = hyper::body::to_bytes(res.into_body()).await.ok();
        let body = body_bytes
            .and_then(|body| String::from_utf8(body.to_vec()).ok())
            .unwrap_or_else(|| "Failed to deserialize error message".into());
        Self::FailedRequest {
            code: status_code,
            message: body,
        }
    }
}

#[async_trait]
pub trait StorageConfigClientInterface {
    async fn get_object(&self, key: String)
        -> Result<Option<GetObjectResponse>, ConfigClientError>;
    async fn put_object(&self, key: String, object: String) -> Result<(), ConfigClientError>;
    async fn delete_object(&self, key: String) -> Result<(), ConfigClientError>;
}

#[derive(Clone, Debug)]
pub struct ConfigClient {}

impl Default for ConfigClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigClient {
    pub fn new() -> Self {
        Self {}
    }

    fn get_uri(&self, path: ConfigServerPath) -> String {
        format!("http://127.0.0.1:{}{}", shared::ENCLAVE_CONFIG_PORT, path)
    }

    async fn get_conn(
        &self,
    ) -> Result<
        (
            SendRequest<hyper::Body>,
            HyperConnection<Connection, hyper::Body>,
        ),
        ConfigClientError,
    > {
        let client_connection: Connection = connection::get_socket(shared::ENCLAVE_CONFIG_PORT)
            .await
            .map_err(BaseClientError::from)?;

        let connection_info = hyper::client::conn::Builder::new()
            .handshake::<Connection, hyper::Body>(client_connection)
            .await
            .map_err(BaseClientError::from)?;

        Ok(connection_info)
    }

    async fn send(
        &self,
        path: ConfigServerPath,
        method: &str,
        payload: hyper::Body,
    ) -> Result<Response<Body>, ConfigClientError> {
        let request = hyper::Request::builder()
            .uri(self.get_uri(path))
            .header("Content-Type", "application/json")
            .method(method)
            .body(payload)
            .expect("Failed to create request");

        let (mut request_sender, connection) = self.get_conn().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::error!("Error with connection to config server in control plane: {e}");
            }
        });

        let response = request_sender
            .send_request(request)
            .await
            .map_err(BaseClientError::from)?;

        Ok(response)
    }

    pub async fn get_e3_token(&self) -> Result<GetE3TokenResponseDataPlane, ConfigClientError> {
        let payload = GetTokenRequestDataPlane::new()
            .into_body()
            .map_err(BaseClientError::from)?;

        let response = self
            .send(ConfigServerPath::GetE3Token, "GET", payload)
            .await?;

        if !response.status().is_success() {
            let status_code = response.status().as_u16();
            let body = response.into_body();
            let body_bytes = hyper::body::to_bytes(body)
                .await
                .map_err(BaseClientError::from)?;
            let message =
                std::str::from_utf8(&body_bytes).unwrap_or("Failed to deserialize message");
            return Err(ConfigClientError::FailedRequest {
                code: status_code,
                message: message.to_string(),
            });
        }

        let result: GetE3TokenResponseDataPlane = self.parse_response(response).await?;

        Ok(result)
    }

    pub async fn get_cert_token(&self) -> Result<GetCertTokenResponseDataPlane, ConfigClientError> {
        let payload = GetTokenRequestDataPlane::new()
            .into_body()
            .map_err(BaseClientError::from)?;

        let response = self
            .send(ConfigServerPath::GetCertToken, "GET", payload)
            .await?;

        if !response.status().is_success() {
            return Err(ConfigClientError::from_response(response).await);
        }

        let result: GetCertTokenResponseDataPlane = self.parse_response(response).await?;

        Ok(result)
    }

    pub async fn post_trx_logs(&self, trx_logs: Vec<TrxContext>) -> Result<(), ConfigClientError> {
        let payload = PostTrxLogsRequest::new(trx_logs)
            .into_body()
            .map_err(BaseClientError::from)?;

        let response = self
            .send(ConfigServerPath::PostTrxLogs, "POST", payload)
            .await?;

        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            log::error!(
                "Error in post_trx_logs request to control plane: {}",
                response.status()
            );
            Err(ConfigClientError::from_response(response).await)
        }
    }

    pub async fn jws(
        &self,
        signature_type: SignatureType,
        url: String,
        nonce: Option<String>,
        payload: String,
        account_id: Option<String>,
    ) -> Result<JwsResponse, ConfigClientError> {
        let payload = JwsRequest::new(signature_type, url, nonce, payload, account_id)
            .into_body()
            .map_err(BaseClientError::from)?;

        log::debug!("Sending JWS request to control plane: {:#?}", payload);

        let response = self
            .send(ConfigServerPath::AcmeSign, "GET", payload)
            .await?;

        if response.status() == StatusCode::OK {
            let result: JwsResponse = self.parse_response(response).await?;
            Ok(result)
        } else {
            log::error!(
                "Error sending jws request to control plane. Response Code: {}",
                response.status()
            );
            Err(ConfigClientError::from_response(response).await)
        }
    }

    pub async fn jwk(&self) -> Result<JwkResponse, ConfigClientError> {
        let response = self
            .send(ConfigServerPath::AcmeJWK, "POST", Body::empty())
            .await?;

        if response.status() == StatusCode::OK {
            let result: JwkResponse = self.parse_response(response).await?;
            Ok(result)
        } else {
            log::error!(
                "Error sending jwk request to control plane. Response Code: {}",
                response.status()
            );
            Err(ConfigClientError::from_response(response).await)
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        res: Response<Body>,
    ) -> Result<T, ConfigClientError> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body)
            .await
            .map_err(BaseClientError::from)?;

        let response_body =
            serde_json::from_slice(&response_body).map_err(BaseClientError::from)?;
        Ok(response_body)
    }

    async fn base_get_object(
        &self,
        key: String,
    ) -> Result<Option<GetObjectResponse>, ConfigClientError> {
        let payload = GetObjectRequest::new(key.clone())
            .into_body()
            .map_err(BaseClientError::from)?;
        let response = self.send(ConfigServerPath::Storage, "GET", payload).await?;

        match response.status() {
            StatusCode::OK => {
                let result: GetObjectResponse = self.parse_response(response).await?;
                Ok(Some(result))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                log::error!(
                    "Error from get object request to control plane. Key: {}, Response Code {}",
                    key,
                    response.status()
                );
                Err(ConfigClientError::from_response(response).await)
            }
        }
    }

    async fn base_put_object(&self, key: String, object: String) -> Result<(), ConfigClientError> {
        let payload = PutObjectRequest::new(key.clone(), object)
            .into_body()
            .map_err(BaseClientError::from)?;
        let response = self.send(ConfigServerPath::Storage, "PUT", payload).await?;

        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            log::error!(
                "Error sending put object request to control plane. Key: {}, Response Code{}",
                key,
                response.status()
            );
            Err(ConfigClientError::from_response(response).await)
        }
    }

    async fn base_delete_object(&self, key: String) -> Result<(), ConfigClientError> {
        let payload = DeleteObjectRequest::new(key.clone())
            .into_body()
            .map_err(BaseClientError::from)?;
        let response = self
            .send(ConfigServerPath::Storage, "DELETE", payload)
            .await?;

        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            log::error!(
                "Error sending delete object request to control plane. Key: {}, Response Code{}",
                key,
                response.status()
            );
            Err(ConfigClientError::from_response(response).await)
        }
    }
}

#[async_trait]
impl StorageConfigClientInterface for ConfigClient {
    async fn get_object(
        &self,
        key: String,
    ) -> Result<Option<GetObjectResponse>, ConfigClientError> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_get_object(key.clone()).await
        })
        .await
    }

    async fn put_object(&self, key: String, object: String) -> Result<(), ConfigClientError> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_put_object(key.clone(), object.clone()).await
        })
        .await
    }

    async fn delete_object(&self, key: String) -> Result<(), ConfigClientError> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_delete_object(key.clone()).await
        })
        .await
    }
}
