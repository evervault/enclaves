pub mod error;
pub mod tcp;
pub use tcp::TcpServer;

#[cfg(feature = "enclave")]
pub mod vsock;
#[cfg(feature = "enclave")]
pub use vsock::VsockServer;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait]
pub trait Listener: Sized {
    type Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin;
    type Error: std::fmt::Debug;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error>;
}

#[cfg(feature = "enclave")]
use tokio_vsock::VsockListener;
#[cfg(feature = "enclave")]
pub async fn get_server_listener(port: u16) -> error::ServerResult<VsockListener> {
    let listener = VsockListener::bind(crate::ENCLAVE_CID, port.into())?;
    Ok(listener)
}

#[cfg(not(feature = "enclave"))]
use tokio::net::TcpListener;
#[cfg(not(feature = "enclave"))]
pub async fn get_server_listener(port: u16) -> error::ServerResult<TcpListener> {
    let addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        port,
    );
    let listener = TcpListener::bind(addr).await?;
    Ok(listener)
}
