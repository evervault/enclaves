use crate::dns;
use crate::dns::InternalAsyncDnsResolver;
use crate::error::Result;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::net::SocketAddr;
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::TokioAsyncResolver;

pub struct E3Proxy {
    #[allow(unused)]
    dns_resolver: TokioAsyncResolver,
}

impl std::default::Default for E3Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Proxy {
    pub fn new() -> Self {
        let dns_resolver = InternalAsyncDnsResolver::new_resolver();
        Self { dns_resolver }
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
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CRYPTO_PORT, Parent).await?;

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

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        dns::get_ip_for_host_with_dns_resolver(&self.dns_resolver, "e3.cages-e3.internal.", 443)
            .await
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        dns::get_ip_for_localhost(7676)
    }
}
