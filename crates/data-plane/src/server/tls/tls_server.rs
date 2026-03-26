use async_trait::async_trait;

#[cfg(feature = "enclave")]
use once_cell::sync::OnceCell;
#[cfg(feature = "enclave")]
use tokio_rustls::rustls::sign::CertifiedKey;

use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use std::sync::Arc;
use tokio_rustls::rustls::server::WantsServerCert;
use tokio_rustls::rustls::ConfigBuilder;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "enclave")]
use crate::acme;

use crate::env::{EnvironmentLoader, NeedCert};
use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use crate::server::tls::cert_resolver::AttestableCertResolver;

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

#[cfg(feature = "enclave")]
pub static TRUSTED_PUB_CERT: OnceCell<Vec<u8>> = OnceCell::new();

impl<S: Listener + Send + Sync> WantsCert<S> {
    /// Get sane defaults for TLS Server config
    fn get_base_config() -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
    }

    pub async fn with_attestable_cert(
        self,
        env_loader: EnvironmentLoader<NeedCert>,
    ) -> ServerResult<TlsServer<S>> {
        log::info!("Creating TLSServer with attestable cert");

        let (env_loader, inter_ca_cert, inter_ca_key_pair) = env_loader
            .load_cert()
            .await
            .map_err(|err| TlsError::CertProvisionerError(err.to_string()))?;

        #[cfg(feature = "enclave")]
        let _: Option<CertifiedKey> = enclave_trusted_cert().await;

        // Once intermediate cert and trusted cert retrieved, write cage initialised vars
        env_loader.finalize_env().unwrap();

        let inter_ca_resolver = AttestableCertResolver::new(inter_ca_cert, inter_ca_key_pair)?;
        let mut tls_config =
            Self::get_base_config().with_cert_resolver(Arc::new(inter_ca_resolver));
        tls_config.alpn_protocols.push(b"http/1.1".to_vec());
        tls_config.alpn_protocols.push(b"h2".to_vec());
        Ok(TlsServer::new(tls_config, self.tcp_server))
    }
}

#[cfg(feature = "enclave")]
async fn enclave_trusted_cert() -> Option<CertifiedKey> {
    match acme::get_trusted_cert().await {
        Ok((pub_key, trusted_cert)) => {
            let _ = TRUSTED_PUB_CERT.set(pub_key);
            Some(trusted_cert)
        }
        Err(e) => {
            //Shutdown if we can't get a trusted cert as it's required.
            log::error!(
                "Failed to get trusted cert for enclave. Shutting down. Cause of error: {e}"
            );
            std::process::exit(1);
        }
    }
}

#[async_trait]
impl<S: Listener + Send + Sync> Listener for TlsServer<S>
where
    TlsError: From<<S as Listener>::Error>,
    <S as Listener>::Connection: ProxiedConnection,
{
    type Connection = TlsStream<<S as Listener>::Connection>;
    type Error = TlsError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let conn = self.inner.accept().await?;
        let accepted_tls_conn = self.tls_acceptor.accept(conn).await?;
        Ok(accepted_tls_conn)
    }
}
