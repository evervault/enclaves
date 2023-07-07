use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::{
    error::Result,
    internal_dns::{self, AsyncDnsResolver},
};

pub struct E3Client {
    socket_addr: Option<SocketAddr>,
    dns_resolver: AsyncDnsResolver,
}

impl Default for E3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Client {
    pub fn new() -> Self {
        let dns_resolver = internal_dns::get_internal_dns_resolver()
            .expect("Failed to create internal dns resolver");

        Self {
            socket_addr: None,
            dns_resolver,
        }
    }

    pub async fn new_conn(&self) -> Result<TcpStream> {
        let socket_addr = match self.socket_addr {
            Some(addr) => addr,
            None => self.get_ip_for_e3().await.unwrap(),
        };

        match tokio::net::TcpStream::connect(socket_addr).await {
            Ok(e3_stream) => Ok(e3_stream),
            Err(e) => {
                panic!("{e}");
            }
        }
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> Result<SocketAddr> {
        internal_dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            "e3.cages-e3.internal.",
            443,
        )
        .await
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> Result<SocketAddr> {
        internal_dns::get_ip_for_localhost(7676)
    }
}
