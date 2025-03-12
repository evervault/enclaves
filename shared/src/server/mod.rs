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
#[cfg(feature = "enclave")]
use crate::ENCLAVE_CID;
#[cfg(not(feature = "enclave"))]
use crate::ENCLAVE_IP;
#[cfg(feature = "enclave")]
use crate::PARENT_CID;
#[cfg(not(feature = "enclave"))]
use crate::PARENT_IP;
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

#[cfg(feature = "enclave")]
pub async fn get_vsock_server(port: u16, cid: CID) -> error::ServerResult<VsockServer> {
    let listener = VsockServer::bind(cid.into(), port.into()).await?;
    Ok(listener)
}

#[cfg(feature = "enclave")]
pub async fn get_vsock_server_with_proxy_protocol(
    port: u16,
    cid: CID,
) -> error::ServerResult<VsockServerWithProxyProtocol> {
    let listener =
        VsockServerWithProxyProtocol::bind(cid.into(), port.into()).await?;
    Ok(listener)
}

#[derive(Clone, Copy, Debug)]
pub enum CID {
    Parent,
    Enclave,
}

impl std::convert::From<CID> for u32 {
    fn from(value: CID) -> Self {
        match value {
          CID::Parent => PARENT_CID,
          CID::Enclave => ENCLAVE_CID,
        }
    }
}

#[cfg(not(feature = "enclave"))]
pub async fn get_vsock_server(port: u16, cid: CID) -> error::ServerResult<TcpServer> {
    let listener = TcpServer::bind(std::net::SocketAddr::new(get_local_ip(cid), port)).await?;
    Ok(listener)
}

#[cfg(not(feature = "enclave"))]
pub async fn get_vsock_server_with_proxy_protocol(
    port: u16,
    cid: CID,
) -> error::ServerResult<TcpServerWithProxyProtocol> {
    let listener =
        TcpServerWithProxyProtocol::bind(std::net::SocketAddr::new(get_local_ip(cid), port))
            .await?;
    Ok(listener)
}

#[cfg(not(feature = "enclave"))]
fn get_local_ip(cid: CID) -> std::net::IpAddr {
    use std::net::Ipv4Addr;
    // Local docker setup
    let ip: u32 = cid.into();
    std::net::IpAddr::V4(ip.parse::<Ipv4Addr>().expect("Invalid IP address"))
}

#[cfg(not(feature = "enclave"))]
pub async fn get_vsock_client(port: u16, cid: CID) -> Result<TcpStream, tokio::io::Error> {
    TcpStream::connect(std::net::SocketAddr::new(get_local_ip(cid), port)).await
}

#[cfg(not(feature = "enclave"))]
impl proxy_protocol::ProxiedConnection for TcpStream {}

#[cfg(feature = "enclave")]
pub async fn get_vsock_client(port: u16, cid: CID) -> Result<VsockStream, tokio::io::Error> {
    VsockStream::connect(cid.into(), port.into()).await
}

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
