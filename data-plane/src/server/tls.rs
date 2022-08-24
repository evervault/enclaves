use shared::server::Listener;

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::server::cert::CertProvider;
use crate::server::error::ServerResult;
use crate::server::error::TlsError;
use tokio_rustls::rustls::ServerConfig;

pub struct TlsServer<S: Listener + Send + Sync> {
    tls_acceptor: TlsAcceptor,
    inner: S,
    creation_time: SystemTime,
    valid_duration: Duration,
}

impl<S: Listener + Send + Sync> TlsServer<S> {
    pub fn builder() -> TlsServerBuilder {
        TlsServerBuilder
    }

    fn new(
        server_config: ServerConfig,
        tcp_server: S,
        creation_time: SystemTime,
        valid_duration: Duration,
    ) -> Self {
        Self {
            tls_acceptor: TlsAcceptor::from(Arc::new(server_config)),
            inner: tcp_server,
            creation_time,
            valid_duration,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
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

impl<S: Listener + Send + Sync> TlsServer<S> {
    pub fn time_till_expiry(&self) -> Duration {
        self.valid_duration
            .checked_sub(
                SystemTime::now()
                    .duration_since(self.creation_time)
                    .unwrap(),
            )
            .unwrap_or(Duration::from_secs(0))
    }
}

impl<S: Listener + Send + Sync> WantsCert<S> {
    pub async fn with_self_signed_cert(self, cert_name: String) -> ServerResult<TlsServer<S>> {
        #[cfg(feature = "enclave")]
        let mut cert_alt_names: Vec<String> = vec![cert_name.clone()];
        #[cfg(not(feature = "enclave"))]
        let cert_alt_names: Vec<String> = vec![cert_name];

        let expiry_time: SystemTime;

        #[cfg(feature = "enclave")]
        {
            use crate::crypto::attest;
            let attestation_doc = attest::get_attestation_doc(None)?;
            expiry_time = attest::get_expiry_time(&attestation_doc)?;
            let attestation_hex_slice = shared::utils::HexSlice::from(attestation_doc.as_slice());
            let attestation_san = format!("{:x}.{cert_name}", attestation_hex_slice);
            cert_alt_names.push(attestation_san);
        }

        #[cfg(not(feature = "enclave"))]
        {
            expiry_time = SystemTime::now() + Duration::from_secs(60 * 60 * 24);
        }

        let creation_time = SystemTime::now();
        let valid_duration = expiry_time.duration_since(creation_time).unwrap();

        let cert_provider = super::cert::SelfSignedCertProvider::new(cert_alt_names)?;
        let (cert, key) = cert_provider.get_cert_and_key().await?;
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        let tls_server = TlsServer::new(config, self.tcp_server, creation_time, valid_duration);
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
