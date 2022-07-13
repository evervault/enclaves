use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

use super::Listener;
use async_trait::async_trait;

pub struct TcpServer {
    inner: TcpListener,
}

impl TcpServer {
    pub async fn bind(addr: SocketAddr) -> super::error::ServerResult<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { inner: listener })
    }
}

#[async_trait]
impl Listener for TcpServer {
    type Connection = TcpStream;
    async fn accept(&mut self) -> super::error::ServerResult<Self::Connection> {
        let (conn, _socket_addr) = self.inner.accept().await?;
        Ok(conn)
    }
}
