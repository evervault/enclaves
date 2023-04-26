use tokio_vsock::{VsockListener, VsockStream};

use super::{error::ServerError, Listener};
use async_trait::async_trait;

pub struct VsockServer {
    inner: VsockListener,
}

impl VsockServer {
    pub async fn bind(cid: u32, port: u32) -> super::error::ServerResult<Self> {
        let listener = VsockListener::bind(cid, port)?;
        Ok(Self { inner: listener })
    }
}

#[async_trait]
impl Listener for VsockServer {
    type Connection = VsockStream;
    type Error = ServerError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let (conn, _socket_addr) = self.inner.accept().await?;
        Ok(conn)
    }
}

pub struct VsockServerWithProxyProtocol {
    inner: VsockListener,
}

impl VsockServerWithProxyProtocol {
    pub async fn bind(cid: u32, port: u32) -> super::error::ServerResult<Self> {
        let listener = VsockListener::bind(cid, port)?;
        Ok(Self { inner: listener })
    }
}

#[async_trait]
impl Listener for VsockServerWithProxyProtocol {
    type Connection = super::proxy_protocol::AcceptedConn<VsockStream>;
    type Error = ServerError;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let (conn, _socket_addr) = self.inner.accept().await?;
        let proxy_protocol_conn = super::proxy_protocol::try_parse_proxy_protocol(conn).await?;
        Ok(proxy_protocol_conn)
    }
}
