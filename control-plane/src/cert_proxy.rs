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

pub struct CertProxy {
    #[allow(unused)]
    dns_resolver: AsyncDnsResolver,
}

impl std::default::Default for CertProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl CertProxy {
    pub fn new() -> Self {
        let dns_resolver =
            internal_dns::get_internal_dns_resolver().expect("Couldn't get internal DNS resolver");
        Self { dns_resolver }
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
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CERT_PORT, Parent).await?;

        println!("Running cert proxy on {}", shared::ENCLAVE_CERT_PORT);
        loop {
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting cert request — {e:?}");
                    continue;
                }
            };
            println!("Forwarding stream to cert provisioner");
            let cert_provisioner_ip = match self.get_ip_for_cert_provisioner().await {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("Error obtaining IP for Cert Provisioner — {e:?}");
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            };

            tokio::spawn(async move {
                let cert_provisioner_stream =
                    match tokio::net::TcpStream::connect(cert_provisioner_ip).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            eprintln!("Failed to connect to Cert Provisioner — {e:?}");
                            Self::shutdown_conn(connection).await;
                            return;
                        }
                    };

                if let Err(e) =
                    shared::utils::pipe_streams(connection, cert_provisioner_stream).await
                {
                    eprintln!("Error streaming from Data Plane to Cert Provisioner — {e:?}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_cert_provisioner(&self) -> Result<SocketAddr> {
        let cert_pro_host = format!("{}.", configuration::get_cert_provisoner_host());
        internal_dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            cert_pro_host.as_str(),
            3000,
        )
        .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_cert_provisioner(&self) -> Result<SocketAddr> {
        internal_dns::get_ip_for_localhost(3000)
    }
}
