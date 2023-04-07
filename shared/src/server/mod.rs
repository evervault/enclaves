pub mod config_server;
#[cfg(feature = "network_egress")]
pub mod egress;
pub mod error;
pub mod health;
pub mod tcp;
pub use tcp::TcpServer;

#[cfg(feature = "enclave")]
pub mod vsock;
#[cfg(feature = "enclave")]
use crate::ENCLAVE_CID;
#[cfg(feature = "enclave")]
use crate::PARENT_CID;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;
#[cfg(feature = "enclave")]
pub use vsock::VsockServer;

#[async_trait]
pub trait Listener: Sized {
    type Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin;
    type Error: std::fmt::Debug + std::fmt::Display;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error>;
}

#[cfg(feature = "enclave")]
pub async fn get_vsock_server(port: u16, cid: CID) -> error::ServerResult<VsockServer> {
    let context_id = match cid {
        CID::Parent => PARENT_CID,
        CID::Enclave => ENCLAVE_CID,
    };
    let listener = VsockServer::bind(context_id, port.into()).await?;
    Ok(listener)
}

pub enum CID {
    Parent,
    Enclave,
}

#[cfg(not(feature = "enclave"))]
pub async fn get_vsock_server(port: u16, _: CID) -> error::ServerResult<TcpServer> {
    use std::net::{IpAddr, Ipv4Addr};
    let listener = TcpServer::bind(std::net::SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        port,
    ))
    .await?;
    Ok(listener)
}

#[cfg(not(feature = "enclave"))]
pub async fn get_vsock_client(port: u16, _: CID) -> Result<TcpStream, tokio::io::Error> {
    TcpStream::connect(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        port,
    ))
    .await
}

#[cfg(feature = "enclave")]
pub async fn get_vsock_client(port: u16, cid: CID) -> Result<VsockStream, tokio::io::Error> {
    let context_id = match cid {
        CID::Parent => PARENT_CID,
        CID::Enclave => ENCLAVE_CID,
    };
    VsockStream::connect(context_id, port.into()).await
}
