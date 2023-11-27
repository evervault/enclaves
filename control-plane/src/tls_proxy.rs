use crate::dns;
use crate::error::Result;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::net::SocketAddr;
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Clone)]
pub struct TlsTargetDetails {
    pub host: String,
    pub port: u16,
}

impl TlsTargetDetails {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
}

//Used for connecting a stream from the data plane to a TLS target
#[derive(Debug, Clone)]
pub struct TlsProxy {
    #[allow(unused)]
    dns_resolver: TokioAsyncResolver,
    target: TlsTargetDetails,
    vsock_port: u16,
}

impl TlsProxy {
    pub fn new(
        target_host: String,
        target_port: u16,
        vsock_port: u16,
        dns_resolver: TokioAsyncResolver,
    ) -> Self {
        let target = TlsTargetDetails::new(target_host, target_port);
        Self {
            dns_resolver,
            target,
            vsock_port,
        }
    }

    #[cfg(feature = "enclave")]
    async fn shutdown_conn(connection: tokio_vsock::VsockStream) {
        if let Err(e) = connection.shutdown(std::net::Shutdown::Both) {
            log::error!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn shutdown_conn(mut connection: tokio::net::TcpStream) {
        if let Err(e) = connection.shutdown().await {
            log::error!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(self.vsock_port, Parent).await?;

        log::info!(
            "Running TLS proxy to {} on {}",
            &self.target.host,
            &self.vsock_port
        );
        let target = self.target.clone();
        loop {
            let target = target.clone();
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("Error accepting connection request in TLS proxy — {e:?}");
                    continue;
                }
            };
            log::info!("Forwarding stream to {}", target.host);
            let target_ip = match self.get_ip_target_host().await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    log::error!("No IP returned for {}", target.host);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
                Err(e) => {
                    log::error!("Error obtaining IP for {} — {e:?}", target.host);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            };

            tokio::spawn(async move {
                let target_stream = match tokio::net::TcpStream::connect(target_ip).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::error!("Failed to connect to {} — {e:?}", target.host);
                        Self::shutdown_conn(connection).await;
                        return;
                    }
                };

                if let Err(e) = shared::utils::pipe_streams(connection, target_stream).await {
                    log::error!("Error streaming from Data Plane to {} — {e:?}", target.host);
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_target_host(&self) -> Result<Option<SocketAddr>> {
        let target = self.target.clone();
        let target_host_dns_name = format!("{}.", target.host);
        dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            target_host_dns_name.as_str(),
            target.port,
        )
        .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_target_host(&self) -> Result<Option<SocketAddr>> {
        use std::net::IpAddr;
        use std::net::Ipv4Addr;
        Ok(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 20, 0, 9)),
            self.target.port,
        )))
    }
}
