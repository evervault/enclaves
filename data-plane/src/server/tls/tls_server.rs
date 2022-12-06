use async_trait::async_trait;
use shared::server::Listener;
use std::sync::Arc;
use tokio_rustls::rustls::server::WantsServerCert;
use tokio_rustls::rustls::ConfigBuilder;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::cert_resolver::SelfSignedCertResolver;
use super::inter_ca_retreiver;

use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use crate::CageContext;

pub struct TlsServer<S: Listener + Send + Sync> {
    tls_acceptor: TlsAcceptor,
    inner: S,
}

impl<S: Listener + Send + Sync> TlsServer<S> {
    fn new(server_config: ServerConfig, tcp_server: S) -> Self {
        Self {
            tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
            inner: tcp_server,
        }
    }
}

/// Mini state machine for wrapping a TCP server with the logic to terminate TLS
pub struct TlsServerBuilder;

impl TlsServerBuilder {
    /// Get instance of TlsServerBuilder, purely for readability
    pub fn new() -> Self {
        Self
    }

    /// Consume underlying server, and move to `WantsCert` state
    pub fn with_server<S: Listener>(self, server: S) -> WantsCert<S> {
        WantsCert { tcp_server: server }
    }
}

impl std::default::Default for TlsServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Final state in provisioning a TLS Server, used to inform the source of the certs
pub struct WantsCert<S: Listener> {
    tcp_server: S,
}

impl<S: Listener + Send + Sync> WantsCert<S> {
    /// Get sane defaults for TLS Server config
    fn get_base_config() -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
    }

    /// Use self signed cert resolver to handle incoming connections
    #[allow(unused)]
    pub fn with_self_signed_cert(self, cage_ctx: CageContext) -> ServerResult<TlsServer<S>> {
        println!("Creating TLSServer with self signed cert");
        let self_signed_cert_resolver = SelfSignedCertResolver::new(cage_ctx)?;
        let config =
            Self::get_base_config().with_cert_resolver(Arc::new(self_signed_cert_resolver));

        Ok(TlsServer::new(config, self.tcp_server))
    }

    pub async fn with_attestable_cert(self, cage_ctx: CageContext) -> ServerResult<TlsServer<S>> {
        println!("Creating TLSServer with attestable cert");
        let inter_ca_retriever = inter_ca_retreiver::InterCaRetreiver::new(cage_ctx.clone());
        let (ca_cert, ca_private_key) = inter_ca_retriever
            .get_intermediate_ca()
            .await
            .map_err(|err| TlsError::CertProvisionerError(err.to_string()))?;
        println!("Received intermediate CA from cert provisioner. Using it with TLS Server.");
        let attestable_cert_resolver = super::cert_resolver::AttestableCertResolver::new(
            ca_cert,
            ca_private_key,
            cage_ctx.clone(),
        )?;
        let tls_config =
            Self::get_base_config().with_cert_resolver(Arc::new(attestable_cert_resolver));
        Ok(TlsServer::new(tls_config, self.tcp_server))
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
