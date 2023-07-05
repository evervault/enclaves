use std::net::SocketAddr;

use deadpool::{async_trait, managed::RecycleResult};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::{
    error::{Result, ServerError},
    internal_dns::{self, AsyncDnsResolver},
};

pub struct E3Connection {
    pub inner: TcpStream,
    #[allow(unused)]
    dns_resolver: AsyncDnsResolver,
}

impl E3Connection {
    pub async fn new() -> Result<Self> {
        let socket_addr = match Self::get_ip_for_e3().await {
            Ok(Some(ip)) => ip,
            Ok(None) => return Err(ServerError::DNSNotFoundError),
            Err(e) => return Err(e),
        };

        let e3_stream = match tokio::net::TcpStream::connect(socket_addr).await {
            Ok(e3_stream) => e3_stream,
            Err(e) => {
                eprintln!("Failed to connect to E3 ({socket_addr}) — {e:?}");
                return Err(ServerError::Io(e));
            }
        };

        let dns_resolver = internal_dns::get_internal_dns_resolver()
            .expect("Failed to create internal dns resolver");

        Ok(Self {
            inner: e3_stream,
            dns_resolver,
        })
    }

    pub async fn close(&mut self) {
        if let Err(e) = self.inner.shutdown().await.map_err(ServerError::Io) {
            println!("Error closing E3 Connection {e}");
        };
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3() -> Result<Option<SocketAddr>> {
        internal_dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            "e3.cages-e3.internal.",
            443,
        )
        .await
    }

    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3() -> Result<Option<SocketAddr>> {
        internal_dns::get_ip_for_localhost(7676)
    }
}

pub struct E3ConnectionManager;
pub type ConnectionPool = deadpool::managed::Pool<E3ConnectionManager>;

#[async_trait]
impl deadpool::managed::Manager for E3ConnectionManager {
    type Type = E3Connection;
    type Error = ServerError;

    async fn create(&self) -> Result<E3Connection> {
        E3Connection::new().await
    }

    async fn recycle(&self, _: &mut E3Connection) -> RecycleResult<ServerError> {
        Ok(()) // todo send message to see if stream is dead
    }

    fn detach(&self, _obj: &mut Self::Type) {}
}

pub fn create_connection_pool(pool_size: usize) -> Result<ConnectionPool> {
    let mgr = E3ConnectionManager;

    ConnectionPool::builder(mgr).max_size(pool_size).build()
        .map_err(|e| ServerError::PoolError(e.to_string()))
}
