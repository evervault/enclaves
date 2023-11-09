pub mod server_cert_verifier;
pub mod tls_client_config;
pub use server_cert_verifier::OpenServerCertVerifier;

use async_trait::async_trait;
use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::header::HeaderValue;
use hyper::{Body, HeaderMap, Response};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio_rustls::rustls::ServerName;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::connection::{self, Connection};
use crate::crypto::token::AttestationAuth;
use shared::{CLIENT_MAJOR_VERSION, CLIENT_VERSION};

#[derive(Debug, Error)]
pub enum BaseClientError {
    #[error("IO Error — {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("Hyper Error — {0:?}")]
    HyperError(#[from] hyper::Error),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
}

#[derive(Clone)]
pub struct BaseClient {
    tls_connector: TlsConnector,
    server_name: ServerName,
    port: u16,
}

#[derive(Clone)]
pub enum AuthType {
    ApiKey(HeaderValue),
    AttestationDoc(AttestationAuth),
}

impl BaseClient {
    pub fn new(tls_connector: TlsConnector, server_name: ServerName, port: u16) -> Self {
        Self {
            tls_connector,
            server_name,
            port,
        }
    }

    async fn get_conn(
        &self,
    ) -> Result<
        (
            SendRequest<hyper::Body>,
            HyperConnection<TlsStream<Connection>, hyper::Body>,
        ),
        BaseClientError,
    > {
        let client_connection: Connection = connection::get_socket(self.port).await?;
        let connection = self
            .tls_connector
            .connect(self.server_name.clone(), client_connection)
            .await?;

        let connection_info = hyper::client::conn::Builder::new()
            .handshake::<TlsStream<Connection>, hyper::Body>(connection)
            .await?;

        Ok(connection_info)
    }

    pub async fn send(
        &self,
        auth_type: Option<AuthType>,
        method: &str,
        uri: &str,
        payload: hyper::Body,
        headers: Option<HeaderMap>,
    ) -> Result<Response<Body>, BaseClientError> {
        let mut request = hyper::Request::builder().uri(uri);
        // if headers have been passed, seed the request with the provided set of headers,
        // but override with required headers to avoid failed reqs.
        if let Some(headers) = headers {
            if let Some(req_header_map) = request.headers_mut() {
                *req_header_map = headers
            }
        }
        let mut request = request
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                format!("Cage-Data-Plane/{}", &*CLIENT_VERSION),
            )
            .header(
                "Accept",
                format!("application/json;version={}", &*CLIENT_MAJOR_VERSION),
            )
            .method(method)
            .body(payload)
            .expect("Failed to create request");

        auth_type.map(|auth| match auth {
            AuthType::ApiKey(header_value) => request.headers_mut().insert("api-key", header_value),
            AuthType::AttestationDoc(auth) => {
                request.headers_mut().insert("attestation-token", auth.doc);
                request.headers_mut().insert("auth-token", auth.token)
            }
        });

        let (mut request_sender, connection) = self.get_conn().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::error!("Error in client connection: {e}");
            }
        });

        let response = request_sender.send_request(request).await?;
        Ok(response)
    }
}

#[async_trait]
pub trait ApiClient {
    type ApiErrorDetails: DeserializeOwned;
    type Error: std::convert::From<BaseClientError>
        + std::convert::From<(hyper::http::response::Parts, Self::ApiErrorDetails)>;

    async fn parse_response<T: DeserializeOwned>(
        response: Response<Body>,
    ) -> Result<T, Self::Error> {
        let (res_info, res_body) = response.into_parts();
        let response_body = hyper::body::to_bytes(res_body)
            .await
            .map_err(BaseClientError::from)?;
        if res_info.status.is_success() {
            let parsed_response: T =
                serde_json::from_slice(&response_body).map_err(BaseClientError::from)?;
            Ok(parsed_response)
        } else {
            let error_details: Self::ApiErrorDetails =
                serde_json::from_slice(&response_body).map_err(BaseClientError::from)?;
            Err((res_info, error_details).into())
        }
    }
}
