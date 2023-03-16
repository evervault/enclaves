use error::Result;
use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::http::StatusCode;
use hyper::{Body, Response};

use serde::de::DeserializeOwned;
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, GetCertTokenResponseDataPlane, GetE3TokenResponseDataPlane,
    GetTokenRequestDataPlane, PostTrxLogsRequest,
};
use shared::server::config_server::routes::ConfigServerPath;

use crate::connection;
use crate::error::{self, Error};

use connection::Connection;

#[derive(Clone)]
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
                eprintln!("Error with connection to config server in control plane: {e}");
            }
        });

        let response = request_sender.send_request(request).await?;
        if !response.status().is_success() {
            return Err(Error::ConfigServer(format!(
                "Unsuccessful response from config server: {}",
                response.status()
            )));
        }

        Ok(response)
    }

    pub async fn get_e3_token(&self) -> Result<GetE3TokenResponseDataPlane> {
        let payload = GetTokenRequestDataPlane::new().into_body()?;

        let response = self
            .send(ConfigServerPath::GetE3Token, "GET", payload)
            .await?;
        let result: GetE3TokenResponseDataPlane = self.parse_response(response).await?;

        Ok(result)
    }

    pub async fn get_cert_token(&self) -> Result<GetCertTokenResponseDataPlane> {
        let payload = GetTokenRequestDataPlane::new().into_body()?;

        let response = self
            .send(ConfigServerPath::GetCertToken, "GET", payload)
            .await?;
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
            println!("Error in message send to control plane");
            Err(Error::ConfigServer(
                "Invalid Response code returned when sending trx logs to control plane "
                    .to_string(),
            ))
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
}
