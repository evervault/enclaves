pub mod config_server;
#[cfg(feature = "network_egress")]
pub mod egress;
pub mod error;
pub mod health;
pub mod proxy_protocol;
pub mod sni;
pub mod tcp;
pub use tcp::{TcpServer, TcpServerWithProxyProtocol};

#[cfg(feature = "enclave")]
pub mod vsock;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;
#[cfg(feature = "enclave")]
pub use vsock::{VsockServer, VsockServerWithProxyProtocol};

#[async_trait]
pub trait Listener: Sized {
    type Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin;
    type Error: std::fmt::Debug + std::fmt::Display;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error>;
}

#[cfg(not(feature = "enclave"))]
impl proxy_protocol::ProxiedConnection for TcpStream {}

#[cfg(feature = "enclave")]
impl proxy_protocol::ProxiedConnection for VsockStream {}

impl<C: proxy_protocol::ProxiedConnection> proxy_protocol::ProxiedConnection
    for tokio_rustls::server::TlsStream<C>
{
    fn proxy_protocol(&self) -> Option<&ppp::v2::Header<'_>> {
        self.get_ref().0.proxy_protocol()
    }

    fn has_proxy_protocol(&self) -> bool {
        self.get_ref().0.has_proxy_protocol()
    }
}
