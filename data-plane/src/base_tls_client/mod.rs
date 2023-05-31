pub mod error;
pub use error::ClientError;
pub mod tls_client_config;

use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::header::HeaderValue;
use hyper::{Body, Response};
use tokio_rustls::rustls::ServerName;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::connection::{self, Connection};
use crate::crypto::token::AttestationAuth;
use shared::{CLIENT_MAJOR_VERSION, CLIENT_VERSION};

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
        ClientError,
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
    ) -> Result<Response<Body>, ClientError> {
        let mut request = hyper::Request::builder()
            .uri(uri)
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
                eprintln!("Error in client connection: {e}");
            }
        });

        let response = request_sender.send_request(request).await?;
        if !response.status().is_success() {
            return Err(ClientError::FailedRequest(response.status()));
        }

        Ok(response)
    }
}
