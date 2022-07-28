use shared::server::Listener;

use async_trait::async_trait;
use std::sync::Arc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::server::cert::CertProvider;
use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use tokio_rustls::rustls::ServerConfig;

pub struct TlsServer<S: Listener + Send + Sync> {
    tls_acceptor: TlsAcceptor,
    inner: S,
}

impl<S: Listener + Send + Sync> TlsServer<S> {
    pub fn builder() -> TlsServerBuilder {
        TlsServerBuilder
    }

    fn new(server_config: ServerConfig, tcp_server: S) -> Self {
        Self {
            tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
            inner: tcp_server,
        }
    }
}

pub struct TlsServerBuilder;

impl TlsServerBuilder {
    pub fn with_server<S: Listener>(self, server: S) -> WantsCert<S> {
        WantsCert { tcp_server: server }
    }
}

pub struct WantsCert<S: Listener> {
    tcp_server: S,
}

impl<S: Listener + Send + Sync> WantsCert<S> {
    pub async fn with_self_signed_cert(self) -> ServerResult<TlsServer<S>> {
        let cert_provider = super::cert::SelfSignedCertProvider::new(vec!["localhost".into()])?;
        let (cert, key) = cert_provider.get_cert_and_key().await?;
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let tls_server = TlsServer::new(config, self.tcp_server);
        Ok(tls_server)
    }

    pub async fn with_remote_cert(self) -> ServerResult<TlsServer<S>> {
        unimplemented!()
    }
}

#[async_trait]
impl<S: Listener + Send + Sync> Listener for TlsServer<S>
where
    TlsError: From<<S as Listener>::Error>,
{
    type Connection = TlsStream<<S as Listener>::Connection>;
    type Error = TlsError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let conn = self.inner.accept().await?;
        let accepted_tls_conn = self.tls_acceptor.accept(conn).await?;
        Ok(accepted_tls_conn)
    }
}
