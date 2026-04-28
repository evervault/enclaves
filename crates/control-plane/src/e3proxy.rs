use crate::dns;
use crate::dns::InternalAsyncDnsResolver;
use crate::error::Result;
use crate::feature_flag::{Context, FeatureFlagProvider};
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    server::Listener,
};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::TokioAsyncResolver;

#[allow(dead_code)]
const E3_HOSTNAME_FLAG: &str = "cages-e3-hostname";
#[allow(dead_code)]
const E3_DEFAULT_HOSTNAME: &str = "e3.cages-e3.internal.";

pub struct E3Proxy {
    #[allow(unused)]
    dns_resolver: TokioAsyncResolver,
    #[allow(unused)]
    feature_flags: Arc<dyn FeatureFlagProvider>,
    #[allow(unused)]
    context: Arc<Context>,
}

impl E3Proxy {
    pub fn new(feature_flags: Arc<dyn FeatureFlagProvider>, context: Arc<Context>) -> Self {
        let dns_resolver = InternalAsyncDnsResolver::new_resolver();
        Self {
            dns_resolver,
            feature_flags,
            context,
        }
    }

    #[cfg(feature = "enclave")]
    async fn shutdown_conn(connection: tokio_vsock::VsockStream) {
        if let Err(e) = connection.shutdown(std::net::Shutdown::Both) {
            log::warn!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn shutdown_conn(mut connection: tokio::net::TcpStream) {
        if let Err(e) = connection.shutdown().await {
            log::warn!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn =
            Bridge::get_listener(shared::ENCLAVE_CRYPTO_PORT, Direction::HostToEnclave).await?;

        log::info!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);
        loop {
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("Error accepting crypto request — {e:?}");
                    continue;
                }
            };
            let e3_ip = match self.get_ip_for_e3().await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    log::error!("No ip returned for E3");
                    Self::shutdown_conn(connection).await;
                    continue;
                }
                Err(e) => {
                    log::error!("Error obtaining IP for E3 — {e:?}");
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            };
            log::info!("Crypto request received, forwarding to {e3_ip}");
            tokio::spawn(async move {
                let e3_stream = match tokio::net::TcpStream::connect(e3_ip).await {
                    Ok(e3_stream) => e3_stream,
                    Err(e) => {
                        log::error!("Failed to connect to E3 ({e3_ip}) — {e:?}");
                        Self::shutdown_conn(connection).await;
                        return;
                    }
                };

                if let Err(e) = shared::utils::pipe_streams(connection, e3_stream).await {
                    log::error!("Error streaming from Data Plane to e3 ({e3_ip})— {e:?}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[allow(dead_code)]
    fn resolve_e3_hostname(&self) -> String {
        self.feature_flags
            .string_feature_flag_with_context(
                E3_HOSTNAME_FLAG,
                &self.context,
                E3_DEFAULT_HOSTNAME.to_string(),
            )
            .unwrap_or_else(|e| {
                log::warn!("FF eval failed for {E3_HOSTNAME_FLAG}, using default: {e:?}");
                E3_DEFAULT_HOSTNAME.to_string()
            })
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        let host = self.resolve_e3_hostname();
        log::debug!("Resolving E3 host: {host}");
        dns::get_ip_for_host_with_dns_resolver(&self.dns_resolver, &host, 443).await
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        dns::get_ip_for_localhost(7676)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_flag::{ContextBuilder, MockFeatureFlagProvider};

    fn make_proxy(mock: MockFeatureFlagProvider) -> E3Proxy {
        let ctx = ContextBuilder::new("test-cage").build().unwrap();
        E3Proxy::new(Arc::new(mock), Arc::new(ctx))
    }

    #[test]
    fn resolve_returns_flag_value_when_set() {
        let mut mock = MockFeatureFlagProvider::new();
        mock.expect_string_feature_flag_with_context()
            .times(1)
            .returning(|_, _, _| Ok("cages-e3-us.ev.global".to_string()));
        let proxy = make_proxy(mock);
        assert_eq!(proxy.resolve_e3_hostname(), "cages-e3-us.ev.global");
    }

    #[test]
    fn resolve_falls_back_to_default_when_flag_eval_errors() {
        let mut mock = MockFeatureFlagProvider::new();
        mock.expect_string_feature_flag_with_context()
            .times(1)
            .returning(|_, _, _| {
                Err(crate::feature_flag::LdError::InitializationFailed)
            });
        let proxy = make_proxy(mock);
        assert_eq!(proxy.resolve_e3_hostname(), E3_DEFAULT_HOSTNAME);
    }

    #[test]
    fn resolve_uses_default_with_noop_provider() {
        use crate::feature_flag::NoopFeatureFlagProvider;
        let ctx = ContextBuilder::new("test-cage").build().unwrap();
        let proxy = E3Proxy::new(Arc::new(NoopFeatureFlagProvider), Arc::new(ctx));
        assert_eq!(proxy.resolve_e3_hostname(), E3_DEFAULT_HOSTNAME);
    }
}
