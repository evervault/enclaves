use async_trait::async_trait;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use shared::server::proxy_protocol::ProxiedConnection;
use shared::server::Listener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio_rustls::rustls::server::WantsServerCert;
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ConfigBuilder;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use super::inter_ca_retreiver;

#[cfg(feature = "enclave")]
use crate::acme;

use crate::env::Environment;
use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use rand::Rng;

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

    pub async fn with_attestable_cert(self) -> ServerResult<TlsServer<S>> {
        println!("Creating TLSServer with attestable cert");
        let (ca_cert, ca_private_key) = Self::get_ca_with_retry().await;
        println!("Received intermediate CA from cert provisioner. Using it with TLS Server.");

        #[cfg(feature = "enclave")]
        let trusted_cert: Option<CertifiedKey> = Some(
            acme::get_trusted_cert()
                .await
                .expect("Failed to get trusted cert"),
        );

        #[cfg(not(feature = "enclave"))] // Don't order trusted certs locally
        let trusted_cert: Option<CertifiedKey> = None;

        //Once intermediate cert and trusted cert retrieved, write cage initialised vars
        Environment::write_startup_complete_env_vars()?;

        let attestable_cert_resolver = super::cert_resolver::AttestableCertResolver::new(
            ca_cert,
            ca_private_key,
            trusted_cert,
        )?;
        let tls_config =
            Self::get_base_config().with_cert_resolver(Arc::new(attestable_cert_resolver));
        Ok(TlsServer::new(tls_config, self.tcp_server))
    }

    async fn get_ca_with_retry() -> (X509, PKey<Private>) {
        let inter_ca_retriever = inter_ca_retreiver::InterCaRetreiver::new();
        let mut attempts = 0;
        loop {
            match inter_ca_retriever.get_intermediate_ca().await {
                Err(e) if attempts < 7 => {
                    let mut rng = rand::thread_rng();
                    let exp_duration =
                        Duration::from_millis(((2 ^ attempts) * 100) + rng.gen_range(50..150));
                    thread::sleep(exp_duration);
                    println!(
                        "Error from provisioner sleeping for {} ms, error: {e}",
                        exp_duration.as_millis()
                    );
                    attempts += 1;
                }
                Err(e) => {
                    println!("Error from provisioner sleeping for 20 seconds: {e}");
                    thread::sleep(Duration::from_secs(20));
                }
                Ok(ca) => break ca,
            }
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
