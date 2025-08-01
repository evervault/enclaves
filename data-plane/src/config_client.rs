use async_trait::async_trait;
use error::Result;
use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::http::StatusCode;
use hyper::{Body, Response};

use serde::de::DeserializeOwned;
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, DeleteObjectRequest, GetCertTokenResponseDataPlane, GetClockSyncResponse,
    GetE3TokenResponseDataPlane, GetObjectRequest, GetObjectResponse, GetTokenRequestDataPlane,
    JwkResponse, JwsRequest, JwsResponse, PostTrxLogsRequest, PutObjectRequest, SignatureType,
};
use shared::server::config_server::routes::ConfigServerPath;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::connection;
use crate::error::{self, Error};

use connection::Connection;

#[async_trait]
pub trait StorageConfigClientInterface {
    async fn get_object(&self, key: String) -> Result<Option<GetObjectResponse>>;
    async fn put_object(&self, key: String, object: String) -> Result<()>;
    async fn delete_object(&self, key: String) -> Result<()>;
    async fn get_time_from_host(&self) -> Result<GetClockSyncResponse>;
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
    ) -> Result<(
        SendRequest<hyper::Body>,
        HyperConnection<Connection, hyper::Body>,
    )> {
        let client_connection: Connection =
            connection::get_socket(shared::ENCLAVE_CONFIG_PORT).await?;

        let connection_info = hyper::client::conn::Builder::new()
            .handshake::<Connection, hyper::Body>(client_connection)
            .await
            .map_err(Error::Hyper)?;

        Ok(connection_info)
    }

    async fn send(
        &self,
        path: ConfigServerPath,
        method: &str,
        payload: hyper::Body,
    ) -> Result<Response<Body>> {
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

        let response = request_sender.send_request(request).await?;

        Ok(response)
    }

    pub async fn get_e3_token(&self) -> Result<GetE3TokenResponseDataPlane> {
        let payload = GetTokenRequestDataPlane::new().into_body()?;

        let response = self
            .send(ConfigServerPath::GetE3Token, "GET", payload)
            .await?;

        if !response.status().is_success() {
            return Err(Error::ConfigServer(format!(
                "Unsuccessful response from config server: {}",
                response.status()
            )));
        }

        let result: GetE3TokenResponseDataPlane = self.parse_response(response).await?;

        Ok(result)
    }

    pub async fn get_cert_token(&self) -> Result<GetCertTokenResponseDataPlane> {
        let payload = GetTokenRequestDataPlane::new().into_body()?;

        let response = self
            .send(ConfigServerPath::GetCertToken, "GET", payload)
            .await?;

        if !response.status().is_success() {
            return Err(Error::ConfigServer(format!(
                "Unsuccessful response from config server: {}",
                response.status()
            )));
        }

        let result: GetCertTokenResponseDataPlane = self.parse_response(response).await?;

        Ok(result)
    }

    pub async fn post_trx_logs(&self, trx_logs: Vec<TrxContext>) -> Result<()> {
        let payload = PostTrxLogsRequest::new(trx_logs).into_body()?;

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
            Err(Error::ConfigServer(
                "Invalid Response code returned when sending trx logs to control plane "
                    .to_string(),
            ))
        }
    }

    pub async fn jws(
        &self,
        signature_type: SignatureType,
        url: String,
        nonce: Option<String>,
        payload: String,
        account_id: Option<String>,
    ) -> Result<JwsResponse> {
        let payload =
            JwsRequest::new(signature_type, url, nonce, payload, account_id).into_body()?;

        log::debug!("Sending JWS request to control plane: {payload:#?}");

        let response = self
            .send(ConfigServerPath::AcmeSign, "GET", payload)
            .await?;

        let response_status = response.status();
        if response_status == StatusCode::OK {
            let result: JwsResponse = self.parse_response(response).await?;
            Ok(result)
        } else {
            let response_body = self.parse_response_body_to_string(response).await?;
            let err_msg = format!(
                "Error sending jws request to control plane. Response Code: {response_status}. Msg: {response_body}"
            );

            log::error!("{err_msg}");
            Err(Error::ConfigServer(err_msg))
        }
    }

    pub async fn jwk(&self) -> Result<JwkResponse> {
        let response = self
            .send(ConfigServerPath::AcmeJWK, "POST", Body::empty())
            .await?;

        let response_status = response.status();
        if response_status == StatusCode::OK {
            let result: JwkResponse = self.parse_response(response).await?;
            Ok(result)
        } else {
            let response_body = self.parse_response_body_to_string(response).await?;
            let err_msg = format!(
                "Error sending jwk request to control plane. Response Code: {response_status}. Msg: {response_body}"
            );

            log::error!("{err_msg}");
            Err(Error::ConfigServer(err_msg))
        }
    }

    async fn parse_response<T: DeserializeOwned>(&self, res: Response<Body>) -> Result<T> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body).await?;

        serde_json::from_slice(&response_body).map_err(|err| {
            Error::ConfigServer(format!(
                "Error parsing response from config server. Error: {err:?}"
            ))
        })
    }

    async fn parse_response_body_to_string(&self, res: Response<Body>) -> Result<String> {
        let body_bytes = hyper::body::to_bytes(res.into_body()).await?;
        String::from_utf8(body_bytes.to_vec()).map_err(Error::FromUtf8Error)
    }

    async fn base_get_object(&self, key: String) -> Result<Option<GetObjectResponse>> {
        let payload = GetObjectRequest::new(key.clone()).into_body()?;
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
                Err(Error::ConfigServer(
                    "Invalid Response code returned when sending getObject request to control plane"
                        .to_string(),
                ))
            }
        }
    }

    async fn base_put_object(&self, key: String, object: String) -> Result<()> {
        let payload = PutObjectRequest::new(key.clone(), object).into_body()?;
        let response = self.send(ConfigServerPath::Storage, "PUT", payload).await?;

        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            log::error!(
                "Error sending put object request to control plane. Key: {}, Response Code{}",
                key,
                response.status()
            );
            Err(Error::ConfigServer(
                "Invalid Response code returned when sending putObject request to control plane "
                    .to_string(),
            ))
        }
    }

    async fn base_delete_object(&self, key: String) -> Result<()> {
        let payload = DeleteObjectRequest::new(key.clone()).into_body()?;
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
            Err(Error::ConfigServer(
                "Invalid Response code returned when sending deleteObject request to control plane"
                    .to_string(),
            ))
        }
    }

    async fn base_get_time_from_host(&self) -> Result<GetClockSyncResponse> {
        let response = self
            .send(ConfigServerPath::Time, "GET", Body::empty())
            .await?;

        if response.status() == StatusCode::OK {
            let result: GetClockSyncResponse = self.parse_response(response).await?;
            Ok(result)
        } else {
            log::error!(
                "Error sending time sync request to control plane. Response Code{}",
                response.status()
            );
            Err(Error::ConfigServer(
                "Invalid Response code returned when sending time request to control plane"
                    .to_string(),
            ))
        }
    }
}

#[async_trait]
impl StorageConfigClientInterface for ConfigClient {
    async fn get_object(&self, key: String) -> Result<Option<GetObjectResponse>> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_get_object(key.clone()).await
        })
        .await
    }

    async fn put_object(&self, key: String, object: String) -> Result<()> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_put_object(key.clone(), object.clone()).await
        })
        .await
    }

    async fn delete_object(&self, key: String) -> Result<()> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_delete_object(key.clone()).await
        })
        .await
    }

    async fn get_time_from_host(&self) -> Result<GetClockSyncResponse> {
        let retry_strategy = ExponentialBackoff::from_millis(500).map(jitter).take(2);

        Retry::spawn(retry_strategy, || async {
            self.base_get_time_from_host().await
        })
        .await
    }
}
