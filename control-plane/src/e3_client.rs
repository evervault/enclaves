use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::{
    error::{Result, ServerError},
    internal_dns,
};

pub struct E3Client {
    addr: Option<SocketAddr>,
}

impl Default for E3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Client {
    pub fn new() -> Self {
        Self { addr: None }
    }

    pub async fn new_conn(&self) -> Result<TcpStream> {
        let socket_addr = match self.addr {
            Some(addr) => addr,
            None => Self::get_ip_for_e3().await?,
        };

        let e3_stream = match tokio::net::TcpStream::connect(socket_addr).await {
            Ok(e3_stream) => e3_stream,
            Err(e) => {
                eprintln!("Failed to connect to E3 ({socket_addr}) — {e:?}");
                return Err(ServerError::Io(e));
            }
        };

        Ok(e3_stream)
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3() -> Result<SocketAddr> {
        let dns_resolver = internal_dns::get_internal_dns_resolver()
            .expect("Failed to create internal dns resolver");

        internal_dns::get_ip_for_host_with_dns_resolver(&dns_resolver, "e3.cages-e3.internal.", 443)
            .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3() -> Result<SocketAddr> {
        internal_dns::get_ip_for_localhost(7676)
    }
}
