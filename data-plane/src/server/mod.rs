pub mod error;
mod tcp;
pub use tcp::TcpServer;

#[cfg(feature = "enclave")]
mod vsock;
#[cfg(feature = "enclave")]
pub use vsock::VsockServer;

#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use tls::TlsServer;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait]
pub trait Listener: Sized {
    type Connection: AsyncRead + AsyncWrite + Send + 'static;
    async fn accept(&mut self) -> error::ServerResult<Self::Connection>;
}
