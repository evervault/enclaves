use crate::server::error::ServerError;
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
    type Error = ServerError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let (conn, _socket_addr) = self.inner.accept().await?;
        Ok(conn)
    }
}
