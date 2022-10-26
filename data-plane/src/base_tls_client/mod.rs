pub mod error;
pub use error::ClientError;
pub mod tls_client_config;

use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::header::HeaderValue;
use hyper::{Body, Response};
use tokio_rustls::rustls::ServerName;
use tokio_rustls::{client::TlsStream, TlsConnector};

#[cfg(not(feature = "enclave"))]
type Connection = tokio::net::TcpStream;
#[cfg(feature = "enclave")]
type Connection = tokio_vsock::VsockStream;

pub struct BaseClient {
    tls_connector: TlsConnector,
    server_name: ServerName,
    port: u16,
}

impl BaseClient {
    pub fn new(tls_connector: TlsConnector, server_name: ServerName, port: u16) -> Self {
        Self {
            tls_connector,
            server_name,
            port,
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_socket(&self) -> Result<Connection, tokio::io::Error> {
        Connection::connect(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            self.port,
        ))
        .await
    }

    #[cfg(feature = "enclave")]
    async fn get_socket(&self) -> Result<Connection, tokio::io::Error> {
        Connection::connect(shared::PARENT_CID, self.port.into()).await
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
        let client_connection: Connection = self.get_socket().await?;
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
        api_key: Option<&HeaderValue>,
        method: &str,
        uri: &str,
        payload: hyper::Body,
    ) -> Result<Response<Body>, ClientError> {
        let mut request = hyper::Request::builder()
            .uri(uri)
            .header("Content-Type", "application/json")
            .method(method)
            .body(payload)
            .expect("Failed to create request");

        if let Some(value) = api_key {
            request.headers_mut().insert("api-key", value.into());
        };

        let (mut request_sender, connection) = self.get_conn().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in client connection: {}", e);
            }
        });

        let response = request_sender.send_request(request).await?;
        if !response.status().is_success() {
            return Err(ClientError::FailedRequest(response.status()));
        }

        Ok(response)
    }
}
