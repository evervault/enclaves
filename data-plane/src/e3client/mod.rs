mod error;
pub use error::Error as E3Error;
mod tls_verifier;

use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::header::HeaderValue;
use hyper::{Body, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, ServerName};
use tokio_rustls::{client::TlsStream, TlsConnector};

fn get_tls_client_config() -> ClientConfig {
    let config_builder = tokio_rustls::rustls::ClientConfig::builder().with_safe_defaults();
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let mut client_config = config_builder
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let mut dangerous = client_config.dangerous();
    dangerous.set_certificate_verifier(std::sync::Arc::new(tls_verifier::E3CertVerifier));
    client_config
}

#[cfg(not(feature = "enclave"))]
type Connection = tokio::net::TcpStream;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;
#[cfg(feature = "enclave")]
type Connection = tokio_vsock::VsockStream;

pub struct E3Client {
    tls_connector: TlsConnector,
    e3_server_name: ServerName,
}

impl std::default::Default for E3Client {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;

#[cfg(not(feature = "enclave"))]
async fn get_socket() -> Result<Connection, tokio::io::Error> {
    TcpStream::connect(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        shared::ENCLAVE_CRYPTO_PORT,
    ))
    .await
}

#[cfg(feature = "enclave")]
async fn get_socket() -> Result<Connection, tokio::io::Error> {
    VsockStream::connect(shared::PARENT_CID, shared::ENCLAVE_CRYPTO_PORT.into()).await
}

impl E3Client {
    pub fn new() -> Self {
        let tls_config = get_tls_client_config();
        Self {
            tls_connector: TlsConnector::from(std::sync::Arc::new(tls_config)),
            e3_server_name: ServerName::try_from("e3.cages-e3.internal")
                .expect("Hardcoded hostname"),
        }
    }

    fn uri(&self, path: &str) -> String {
        format!("https://e3.cages-e3.internal{}", path)
    }

    async fn get_conn(
        &self,
    ) -> Result<
        (
            SendRequest<hyper::Body>,
            HyperConnection<TlsStream<Connection>, hyper::Body>,
        ),
        E3Error,
    > {
        let client_connection: Connection = get_socket().await?;
        let connection = self
            .tls_connector
            .connect(self.e3_server_name.clone(), client_connection)
            .await?;

        let connection_info = hyper::client::conn::Builder::new()
            .handshake::<TlsStream<Connection>, hyper::Body>(connection)
            .await?;

        Ok(connection_info)
    }

    async fn send<V>(
        &self,
        api_key: V,
        path: &str,
        payload: hyper::Body,
    ) -> Result<Response<Body>, E3Error>
    where
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        let decrypt_request = hyper::Request::builder()
            .uri(self.uri(path))
            .header("api-key", api_key)
            .method("POST")
            .body(payload)
            .expect("Failed to create request");

        // TODO: connection pooling
        let (mut request_sender, connection) = self.get_conn().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in e3 connection: {}", e);
            }
        });

        let response = request_sender.send_request(decrypt_request).await?;
        if !response.status().is_success() {
            return Err(E3Error::FailedRequest(response.status()));
        }

        Ok(response)
    }

    pub async fn decrypt<T, V>(&self, api_key: V, payload: DecryptRequest) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        let response = self
            .send(api_key, "/decrypt", payload.try_into_body()?)
            .await?;
        self.parse_response(response).await
    }

    pub async fn encrypt<T, V>(&self, api_key: V, payload: EncryptRequest) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        let response = self
            .send(api_key, "/encrypt", payload.try_into_body()?)
            .await?;
        self.parse_response(response).await
    }

    pub async fn authenticate<V>(&self, api_key: V, payload: AuthRequest) -> Result<bool, E3Error>
    where
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        let response = self
            .send(api_key, "/authenticate", payload.try_into_body()?)
            .await?;

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
    team_uuid: String,
    app_uuid: String,
}

impl E3Payload for AuthRequest {}

impl std::convert::From<&crate::CageContext> for AuthRequest {
    fn from(context: &crate::CageContext) -> Self {
        Self {
            team_uuid: context.team_uuid().to_string(),
            app_uuid: context.app_uuid().to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDataEntry {
    range: (usize, usize),
    value: String,
}

impl EncryptedDataEntry {
    pub fn range(&self) -> (usize, usize) {
        self.range
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn new(range: (usize, usize), value: String) -> Self {
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
pub struct EncryptRequest {
    team_uuid: String,
    app_uuid: String,
    data: Value,
}

impl E3Payload for EncryptRequest {}
impl EncryptRequest {
    pub fn data(&self) -> &Value {
        &self.data
    }
}

impl std::convert::From<(Value, &crate::CageContext)> for EncryptRequest {
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
