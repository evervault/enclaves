mod error;
pub use error::Error as E3Error;
mod tls_verifier;

use hyper::client::conn::{Connection as HyperConnection, SendRequest};
use hyper::header::HeaderValue;
use serde::de::DeserializeOwned;
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

impl E3Client {
    pub fn new() -> Self {
        let tls_config = get_tls_client_config();
        Self {
            tls_connector: TlsConnector::from(std::sync::Arc::new(tls_config)),
            e3_server_name: ServerName::try_from("e3.cages-e3.internal").unwrap(),
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
        let client_connection =
            shared::client::get_client_socket(shared::ENCLAVE_CRYPTO_PORT).await?;

        let connection = self
            .tls_connector
            .connect(self.e3_server_name.clone(), client_connection)
            .await?;

        let connection_info = hyper::client::conn::Builder::new()
            .handshake::<TlsStream<Connection>, hyper::Body>(connection)
            .await?;

        Ok(connection_info)
    }

    async fn send<T, V>(&self, api_key: V, path: &str, payload: hyper::Body) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
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

        let e3_response = request_sender.send_request(decrypt_request).await?;
        let response_body = hyper::body::to_bytes(e3_response.into_body())
            .await?
            .to_vec();

        Ok(serde_json::from_slice(response_body.as_slice())?)
    }

    pub async fn decrypt<'a, T, V>(&self, api_key: V, payload: E3Payload<'a>) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        self.send(api_key, "/decrypt", payload.try_into()?).await
    }

    pub async fn encrypt<'a, T, V>(&self, api_key: V, payload: E3Payload<'a>) -> Result<T, E3Error>
    where
        T: DeserializeOwned,
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        self.send(api_key, "/encrypt", payload.try_into()?).await
    }

    pub async fn authenticate<'a, V>(&self, api_key: V) -> Result<bool, E3Error>
    where
        HeaderValue: TryFrom<V>,
        hyper::http::Error: From<<HeaderValue as TryFrom<V>>::Error>,
    {
        let response: Value = self
            .send(api_key, "/authenticate", hyper::Body::empty())
            .await?;

        Ok(response.is_object())
    }
}

pub struct E3Payload<'a>(Option<&'a Value>);

impl<'a> std::convert::From<&'a Value> for E3Payload<'a> {
    fn from(val: &'a Value) -> Self {
        Self(Some(val))
    }
}

impl<'a> std::convert::TryInto<hyper::Body> for E3Payload<'a> {
    type Error = E3Error;
    fn try_into(self) -> Result<hyper::Body, E3Error> {
        let body = match self.0 {
            None => hyper::Body::empty(),
            Some(val) => hyper::Body::from(serde_json::to_vec(val)?),
        };
        Ok(body)
    }
}
