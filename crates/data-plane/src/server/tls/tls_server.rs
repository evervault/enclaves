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

/// Get sane defaults for TLS Server config
fn get_base_config() -> ConfigBuilder<ServerConfig, WantsServerCert> {
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
}

pub async fn build_attestable_server_config(
    env_loader: EnvironmentLoader<NeedCert>,
) -> ServerResult<ServerConfig> {
    log::info!("Building attestable TLS server config");

    let (env_loader, inter_ca_cert, inter_ca_key_pair) = env_loader
        .load_cert()
        .await
        .map_err(|err| TlsError::CertProvisionerError(err.to_string()))?;

    #[cfg(feature = "enclave")]
    let _: CertifiedKey = enclave_trusted_cert().await?;

    // Once intermediate cert and trusted cert retrieved, write cage initialised vars
    env_loader
        .finalize_env()
        .map_err(|err| TlsError::FinalizeEnvError(err.to_string()))?;

    let inter_ca_resolver = AttestableCertResolver::new(inter_ca_cert, inter_ca_key_pair)?;
    let mut tls_config = get_base_config().with_cert_resolver(Arc::new(inter_ca_resolver));
    tls_config.alpn_protocols.push(b"http/1.1".to_vec());
    tls_config.alpn_protocols.push(b"h2".to_vec());
    Ok(tls_config)
}

impl<S: Listener + Send + Sync> WantsCert<S> {
    pub async fn with_attestable_cert(
        self,
        env_loader: EnvironmentLoader<NeedCert>,
    ) -> ServerResult<TlsServer<S>> {
        let tls_config = build_attestable_server_config(env_loader).await?;
        Ok(TlsServer::new(tls_config, self.tcp_server))
    }
}

#[cfg(feature = "enclave")]
async fn enclave_trusted_cert() -> ServerResult<CertifiedKey> {
    match acme::get_trusted_cert().await {
        Ok((pub_key, trusted_cert)) => {
            let _ = TRUSTED_PUB_CERT.set(pub_key);
            Ok(trusted_cert)
        }
        Err(e) => {
            // The trusted cert is required, so surface the failure to the boot task. The
            // healthcheck server owns the process lifetime and will report the Enclave as
            // unhealthy — the process must not exit here.
            log::error!("Failed to get trusted cert for enclave. Cause of error: {e}");
            Err(TlsError::TrustedCertError(e.to_string()))
        }
    }
}

#[cfg(all(test, feature = "enclave"))]
mod tests {
    use super::*;

    /// Regression test for the process kill that used to live in `enclave_trusted_cert`.
    ///
    /// There is no config server or ACME provider reachable from a unit test, so
    /// `acme::get_trusted_cert` cannot succeed here. The assertion that matters is that the
    /// failure comes back as an `Err` — before this changed, this call site ran
    /// `std::process::exit(1)` and would have taken the test runner down with it.
    #[tokio::test]
    async fn failing_trusted_cert_fetch_returns_an_error_instead_of_exiting() {
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(30), enclave_trusted_cert())
                .await
                .expect("Timed out waiting for the trusted cert fetch to fail");

        assert!(
            result.is_err(),
            "Expected the trusted cert fetch to fail in a unit test environment"
        );
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
