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
    type Connection: AsyncRead + AsyncWrite + Send + 'static;
    type Error;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error>;
}
