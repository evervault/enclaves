use std::sync::Arc;

use crate::acme::error::AcmeError;
use async_trait::async_trait;
use hyper::client::conn::{Connection as HyperConnection, SendRequest};

use hyper::{Body, Response};
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::connection::{self, Connection};

#[async_trait]
pub trait AcmeClientInterface {
    async fn send(&self, request: hyper::Request<Body>) -> Result<Response<Body>, AcmeError>;
}

#[derive(Clone)]
pub struct AcmeClient {
    tls_connector: TlsConnector,
    server_name: ServerName,
    port: u16,
}

impl AcmeClient {
    #[allow(unused)]
    fn new(server_name: ServerName) -> Self {
        let mut root_cert_store = RootCertStore::empty();

        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(config));

        Self {
            tls_connector,
            server_name,
            port: shared::ENCLAVE_ACME_PORT,
        }
    }

    async fn get_conn(
        &self,
    ) -> Result<
        (
            SendRequest<hyper::Body>,
            HyperConnection<TlsStream<Connection>, hyper::Body>,
        ),
        AcmeError,
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
}

#[async_trait]
impl AcmeClientInterface for AcmeClient {
    async fn send(&self, request: hyper::Request<Body>) -> Result<Response<Body>, AcmeError> {
        let (mut request_sender, connection) = self.get_conn().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in client connection: {e}");
            }
        });

        let response = request_sender.send_request(request).await?;

        Ok(response)
    }
}
