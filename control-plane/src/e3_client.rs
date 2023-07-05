use std::net::{SocketAddr};

use deadpool::{async_trait, managed::RecycleResult};
use tokio::{net::TcpStream, io::AsyncWriteExt};

use crate::error::{ServerError, Result};

pub struct E3Connection {
	pub inner: TcpStream,
}

impl E3Connection {
	pub async fn new() -> Result<Self> {
		let socket_addr = match Self::get_ip_for_e3().await {
			Ok(Some(ip)) => ip,
			Ok(None) => panic!("find an answer"),
			Err(e) => return Err(e) // todo better error
		};

		let e3_stream = match tokio::net::TcpStream::connect(socket_addr).await {
			Ok(e3_stream) => e3_stream,
			Err(e) => {
					eprintln!("Failed to connect to E3 ({socket_addr}) — {e:?}");
					return Err(ServerError::Io(e));
			}
		};

		Ok(Self {
			inner: e3_stream
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
    use crate::internal_dns;
			internal_dns::get_ip_for_localhost(7676)
	}
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
	use crate::internal_dns;
	internal_dns::get_ip_for_localhost(7676)
}


pub struct E3ConnectionManager;
pub type ConnectionPool = deadpool::managed::Pool<E3ConnectionManager>;

#[async_trait]
impl deadpool::managed::Manager for E3ConnectionManager {
		type Type = TcpStream;
		type Error = ServerError;

		async fn create(&self) -> Result<TcpStream> {
			let socket_addr = match get_ip_for_e3().await {
				Ok(Some(ip)) => ip,
				Ok(None) => panic!("find an answer"),
				Err(e) => return Err(e) // todo better error
			};
	
			tokio::net::TcpStream::connect(socket_addr).await.map_err(ServerError::Io)
		}

    // async fn recycle(&self, obj: &mut Self::Type) -> RecycleResult<Self::Error>;
		async fn recycle(&self, conn: &mut TcpStream) -> RecycleResult<ServerError> {
			Ok(())
		}

    fn detach(&self, _obj: &mut Self::Type) {}
}

pub fn create_connection_pool(pool_size: usize) -> ConnectionPool {
	let mgr = E3ConnectionManager;

	if let Ok(pool) = ConnectionPool::builder(mgr).max_size(pool_size).build() {
		return pool
	}

	panic!("couldn't build pool.. :(")
}