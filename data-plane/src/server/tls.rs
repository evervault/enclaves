use shared::server::Listener;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use crate::server::tls::cert::CertProvider;
use rustls_pemfile::Item;
use shared::server::tcp::TcpServer;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

pub struct TlsServer {
    tls_acceptor: TlsAcceptor,
    inner: TcpServer,
}

impl TlsServer {
    pub fn builder() -> TlsServerBuilder {
        TlsServerBuilder
    }

    fn new(server_config: ServerConfig, tcp_server: TcpServer) -> Self {
        Self {
            tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
            inner: tcp_server,
        }
    }
}

pub struct TlsServerBuilder;

impl TlsServerBuilder {
    pub fn with_tcp_server(self, server: TcpServer) -> WantsCert {
        WantsCert { tcp_server: server }
    }
}

pub struct WantsCert {
    tcp_server: TcpServer,
}

impl WantsCert {
    #[cfg(feature = "local-cert")]
    pub async fn with_local_cert(self) -> ServerResult<TlsServer> {
        let (cert, key) = cert::LocalCertProvider.get_cert_and_key().await?;
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let tls_server = TlsServer::new(config, self.tcp_server);
        Ok(tls_server)
    }

    pub async fn with_remote_cert(self) -> ServerResult<TlsServer> {
        unimplemented!()
    }
}

#[async_trait]
impl Listener for TlsServer {
    type Connection = TlsStream<TcpStream>;
    type Error = TlsError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let conn = self.inner.accept().await?;
        let accepted_tls_conn = self.tls_acceptor.accept(conn).await?;
        Ok(accepted_tls_conn)
    }
}

mod cert {
    use super::*;
    use crate::server::error::TlsError;
    #[async_trait]
    pub(super) trait CertProvider {
        async fn get_cert_and_key(&self) -> ServerResult<(Certificate, PrivateKey)>;
    }

    #[cfg(feature = "local-cert")]
    pub(super) struct LocalCertProvider;

    #[cfg(feature = "local-cert")]
    impl LocalCertProvider {
        fn get_cert_location(&self) -> String {
            std::env::var("DATA_PLANE_CERT")
                .unwrap_or_else(|_| "./data-plane.localhost.pem".to_string())
        }

        fn get_key_location(&self) -> String {
            std::env::var("DATA_PLANE_PK")
                .unwrap_or_else(|_| "./data-plane.localhost-key.pem".to_string())
        }
    }

    #[cfg(feature = "local-cert")]
    #[async_trait]
    impl CertProvider for LocalCertProvider {
        async fn get_cert_and_key(&self) -> ServerResult<(Certificate, PrivateKey)> {
            let cert = self.get_cert_location();
            let imported_cert = import_cert(cert.as_str())?.ok_or(TlsError::NoCertFound)?;

            let key = self.get_key_location();
            let imported_key = import_key(key.as_str())?.ok_or(TlsError::NoKeyFound)?;

            Ok((imported_cert, imported_key))
        }
    }

    // In the enclave we will require a RemoteCertProvider impl.
    // struct RemoteCertProvider;

    fn import_cert(location: &str) -> ServerResult<Option<Certificate>> {
        let item_filter = |item: Item| -> Option<Certificate> {
            match item {
                Item::X509Certificate(cert) => Some(Certificate(cert)),
                _ => None,
            }
        };
        read_pemfile(location, item_filter)
    }

    fn import_key(location: &str) -> ServerResult<Option<PrivateKey>> {
        let item_filter = |item: Item| -> Option<PrivateKey> {
            match item {
                Item::PKCS8Key(key) | Item::RSAKey(key) | Item::ECKey(key) => Some(PrivateKey(key)),
                _ => None,
            }
        };
        read_pemfile(location, item_filter)
    }

    fn read_pemfile<T: Sized, F: Fn(Item) -> Option<T>>(
        location: &str,
        filter_item: F,
    ) -> ServerResult<Option<T>> {
        let file_path = std::path::Path::new(location);
        let file = std::fs::File::open(file_path)?;
        let mut buffered_file = std::io::BufReader::new(file);
        for parsed_item in
            std::iter::from_fn(|| rustls_pemfile::read_one(&mut buffered_file).transpose())
        {
            match filter_item(parsed_item?) {
                Some(matched_item) => return Ok(Some(matched_item)),
                _ => continue,
            };
        }
        Ok(None)
    }
}
