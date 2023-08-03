#[cfg(feature = "enclave")]
use crate::configuration;
use crate::error::Result;
use crate::internal_dns;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::net::SocketAddr;
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

type AsyncDnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

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
    dns_resolver: AsyncDnsResolver,
    target: TlsTargetDetails,
    vsock_port: u16
}

impl TlsProxy {
    pub fn new(target_host: String, target_port: u16, vsock_port: u16) -> Self {
        let dns_resolver =
            internal_dns::get_internal_dns_resolver().expect("Couldn't get internal DNS resolver");
        let target = TlsTargetDetails::new(target_host, target_port);
        Self { dns_resolver, target, vsock_port }
    }

    #[cfg(feature = "enclave")]
    async fn shutdown_conn(connection: tokio_vsock::VsockStream) {
        if let Err(e) = connection.shutdown(std::net::Shutdown::Both) {
            eprintln!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn shutdown_conn(mut connection: tokio::net::TcpStream) {
        if let Err(e) = connection.shutdown().await {
            eprintln!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(self.vsock_port, Parent).await?;

        println!("Running TLS proxy to {} on {}", &self.target.host.clone(), &self.vsock_port);
        let target = self.target.clone();
        loop {
            let target = target.clone();
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting connection request in TLS proxy — {e:?}");
                    continue;
                }
            };
            println!("Forwarding stream to {}", target.host);
            let target_ip = match self.get_ip_target_host().await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    eprintln!("No IP returned for {}", target.host);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
                Err(e) => {
                    eprintln!("Error obtaining IP for {} — {e:?}", target.host);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            };

            tokio::spawn(async move {
                let target_stream =
                    match tokio::net::TcpStream::connect(target_ip).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            eprintln!("Failed to connect to {} — {e:?}", target.host);
                            Self::shutdown_conn(connection).await;
                            return;
                        }
                    };

                if let Err(e) =
                    shared::utils::pipe_streams(connection, target_stream).await
                {
                    eprintln!("Error streaming from Data Plane to {} — {e:?}", target.host);
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
        internal_dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            target_host_dns_name.as_str(),
            target.port,
        )
        .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_target_host(&self) -> Result<Option<SocketAddr>> {
        internal_dns::get_ip_for_localhost(self.target.port)
    }
}
