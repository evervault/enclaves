use crate::dns;
use crate::error::Result;
use shared::server::sni::get_hostname;
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    server::Listener,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Clone)]
pub struct TlsTargetDetails {
    pub hosts: Vec<String>,
    pub port: u16,
}

impl TlsTargetDetails {
    pub fn new(hosts: Vec<String>, port: u16) -> Self {
        Self { hosts, port }
    }
}

//Used for connecting a stream from the data plane to a TLS target
#[derive(Debug, Clone)]
pub struct TlsProxy {
    #[allow(unused)]
    dns_resolver: TokioAsyncResolver,
    targets: TlsTargetDetails,
    vsock_port: u16,
}

impl TlsProxy {
    pub fn new(
        hosts: Vec<String>,
        port: u16,
        vsock_port: u16,
        dns_resolver: TokioAsyncResolver,
    ) -> Self {
        let targets = TlsTargetDetails::new(hosts, port);
        Self {
            dns_resolver,
            targets,
            vsock_port,
        }
    }

    fn valid_targets(&self) -> Vec<&str> {
        self.targets
            .hosts
            .iter()
            .map(|host| host.as_str())
            .collect()
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
        let mut enclave_conn =
            Bridge::get_listener(self.vsock_port, Direction::HostToEnclave).await?;

        log::info!(
            "Running TLS proxy to {:?} on {}",
            &self.targets,
            &self.vsock_port
        );
        loop {
            let (connection, target, initial_bytes) = match enclave_conn.accept().await {
                Ok(mut conn) => {
                    // Extract SNI header and check it's for the TLS server's valid hostnames
                    let mut buf = vec![0u8; 4096];
                    let n = conn.read(&mut buf).await?;
                    let initial_slice = &buf[..n];
                    let hostname = get_hostname(initial_slice.to_vec()).ok(); // Clone the slice into a new Vec

                    match hostname {
                        Some(host) if self.valid_targets().contains(&host.as_str()) => {
                            log::info!("SNI header found for {}. Valid host, forwarding traffic from data plane.", host);
                            let initial_bytes = initial_slice.to_vec(); // Clone the slice into a new Vec
                            (conn, host, initial_bytes)
                        }
                        Some(host) => {
                            log::error!(
                                "SNI header found for invalid host {}. Shutting down connection",
                                host
                            );
                            Self::shutdown_conn(conn).await;
                            continue;
                        }
                        None => {
                            log::error!("No SNI header found in request");
                            Self::shutdown_conn(conn).await;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Error accepting connection request in TLS proxy — {e:?}");
                    continue;
                }
            };
            let target_clone = target.clone();
            log::info!("Forwarding stream to {}", target);
            let target_ip = match self.get_ip_target_host(target).await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    log::error!("No IP returned for {}", target_clone);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
                Err(e) => {
                    log::error!("Error obtaining IP for {} — {e:?}", target_clone);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            };

            tokio::spawn(async move {
                let mut target_stream = match tokio::net::TcpStream::connect(target_ip).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::error!("Failed to connect to {} — {e:?}", target_clone);
                        Self::shutdown_conn(connection).await;
                        return;
                    }
                };

                if let Err(e) = target_stream.write_all(&initial_bytes).await {
                    log::error!("Failed to send initial data to {} — {e:?}", target_clone);
                    Self::shutdown_conn(connection).await;
                    return;
                }

                if let Err(e) = shared::utils::pipe_streams(connection, target_stream).await {
                    log::error!(
                        "Error streaming from Data Plane to {} — {e:?}",
                        target_clone
                    );
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_target_host(&self, target: String) -> Result<Option<SocketAddr>> {
        let target_host_dns_name = format!("{}.", target);
        let port = self.targets.port;
        dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            target_host_dns_name.as_str(),
            port,
        )
        .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_target_host(&self, _target: String) -> Result<Option<SocketAddr>> {
        dns::get_ip_for_localhost(self.targets.port)
    }
}
