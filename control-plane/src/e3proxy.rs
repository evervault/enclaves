use crate::error::Result;
#[cfg(feature = "enclave")]
use rand::prelude::IteratorRandom;
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

type AsyncDnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub struct E3Proxy {
    #[allow(unused)]
    dns_resolver: AsyncDnsResolver,
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

    pub async fn listen(self) -> Result<()> {
        let enclave_conn =
            match shared::server::get_server_listener(shared::ENCLAVE_CRYPTO_PORT).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!(
                        "An error occurred while creating a crypto listener — {:?}",
                        e
                    );
                    return Err(e.into());
                }
            };
        #[cfg(feature = "enclave")]
        let mut enclave_conn = enclave_conn;

        loop {
            if let Ok((connection, _client_socket_addr)) = enclave_conn.accept().await {
                println!("Crypto request received");
                let e3_ip = self.get_ip_for_e3().await; // TODO: cache
                println!("IP for E3 obtained");
                tokio::spawn(async move {
                    let e3_stream = tokio::net::TcpStream::connect((e3_ip, 443))
                        .await
                        .expect("Failed to connect to e3");

                    if let Err(e) = shared::utils::pipe_streams(connection, e3_stream).await {
                        eprintln!("Error streaming from Data Plane to e3 — {:?}", e);
                    }
                });
            }
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> IpAddr {
        self.dns_resolver
            .lookup_ip("e3.cages-e3.internal.")
            .await
            .unwrap()
            .iter()
            .choose(&mut rand::thread_rng())
            .unwrap()
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }
}
