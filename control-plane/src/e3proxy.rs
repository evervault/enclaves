use crate::error::Result;
#[cfg(feature = "enclave")]
use rand::prelude::IteratorRandom;
use shared::server::Listener;
#[cfg(not(feature = "enclave"))]
use shared::server::TcpServer;
#[cfg(feature = "enclave")]
use shared::server::VsockServer;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

type AsyncDnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub struct E3Proxy {
    #[allow(unused)]
    dns_resolver: AsyncDnsResolver,
}

impl std::default::Default for E3Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Proxy {
    pub fn new() -> Self {
        let aws_internal_dns_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253));
        let dns_resolver = AsyncResolver::tokio(
            ResolverConfig::from_parts(
                None,
                vec![],
                NameServerConfigGroup::from_ips_clear(&[aws_internal_dns_ip], 53, true),
            ),
            ResolverOpts::default(),
        )
        .expect("Failed to create internal dns resolver");
        Self { dns_resolver }
    }

    #[cfg(feature = "enclave")]
    async fn shutdown_conn(connection: tokio_vsock::VsockStream) {
        if let Err(e) = connection.shutdown(std::net::Shutdown::Both) {
            eprintln!("Failed to shutdown data plane connection — {:?}", e);
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn shutdown_conn(mut connection: tokio::net::TcpStream) {
        if let Err(e) = connection.shutdown().await {
            eprintln!("Failed to shutdown data plane connection — {:?}", e);
        }
    }

    pub async fn listen(self) -> Result<()> {
        #[cfg(feature = "enclave")]
        let mut enclave_conn =
            VsockServer::bind(shared::PARENT_CID, shared::ENCLAVE_CRYPTO_PORT.into()).await?;

        #[cfg(not(feature = "enclave"))]
        let mut enclave_conn = TcpServer::bind(std::net::SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            shared::ENCLAVE_CRYPTO_PORT,
        ))
        .await?;

        println!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);
        loop {
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting crypto request — {:?}", e);
                    continue;
                }
            };
            println!("Crypto request received");
            let e3_ip = match self.get_ip_for_e3().await {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    eprintln!("No ip returned for E3");
                    Self::shutdown_conn(connection).await;
                    continue;
                }
                Err(e) => {
                    eprintln!("Error obtaining IP for E3 — {:?}", e);
                    Self::shutdown_conn(connection).await;
                    continue;
                }
            }; // TODO: cache
            println!("IP for E3 obtained");
            tokio::spawn(async move {
                let e3_stream = match tokio::net::TcpStream::connect((e3_ip, 443)).await {
                    Ok(e3_stream) => e3_stream,
                    Err(e) => {
                        eprintln!("Failed to connect to E3 — {:?}", e);
                        Self::shutdown_conn(connection).await;
                        return;
                    }
                };

                if let Err(e) = shared::utils::pipe_streams(connection, e3_stream).await {
                    eprintln!("Error streaming from Data Plane to e3 — {:?}", e);
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> Result<Option<IpAddr>> {
        let ip = self
            .dns_resolver
            .lookup_ip("e3.cages-e3.internal.")
            .await?
            .iter()
            .choose(&mut rand::thread_rng());
        Ok(ip)
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> Result<Option<IpAddr>> {
        Ok(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
    }
}
