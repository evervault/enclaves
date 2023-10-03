use std::{net::AddrParseError, num::ParseIntError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VsockParseError {
    #[error(
        "Failed to parse vsock address. Incorrect number of tokens found. Expected 2, Received {0}"
    )]
    InvalidAddress(usize),
    #[error("Failed to parse tokens in vsock address. Expected 2 numeric tokens separated by a colon (CID:PORT) e.g. 1234:8008")]
    TokenParseError(#[from] ParseIntError),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse tcp socket address - {0}")]
    TcpParseError(#[from] AddrParseError),
    #[error(transparent)]
    VsockParseError(#[from] VsockParseError),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    Vsock(u32, u32),
    Tcp(std::net::SocketAddr),
}

impl Address {
    pub fn new_tcp_address(addr: &str) -> Result<Self, Error> {
        let socket_addr = addr.parse()?;
        Ok(Self::Tcp(socket_addr))
    }

    pub fn new_vsock_address(addr: &str) -> Result<Self, Error> {
        let addr_parts: Vec<&str> = addr.split(':').collect();
        if addr_parts.len() != 2 {
            return Err(Error::VsockParseError(VsockParseError::InvalidAddress(
                addr_parts.len(),
            )));
        }

        #[allow(clippy::get_first)]
        let parsed_cid = match addr_parts.get(0).unwrap().trim().parse::<u32>() {
            Ok(cid) => cid,
            Err(e) => return Err(Error::VsockParseError(VsockParseError::from(e))),
        };

        let parsed_port = match addr_parts.get(1).unwrap().trim().parse::<u32>() {
            Ok(port) => port,
            Err(e) => return Err(Error::VsockParseError(VsockParseError::from(e))),
        };

        Ok(Self::Vsock(parsed_cid, parsed_port))
    }

    /// Convert an address into a listener capable of accepting incoming connections to proxy to the destination
    pub async fn into_listener(self) -> Result<SourceConnection, tokio::io::Error> {
        match self {
            Self::Tcp(tcp_addr) => {
                let listener = tokio::net::TcpListener::bind(tcp_addr).await?;
                Ok(SourceConnection::Tcp(listener))
            }
            Self::Vsock(cid, port) => {
                let listener = tokio_vsock::VsockListener::bind(cid, port)?;
                Ok(SourceConnection::Vsock(listener))
            }
        }
    }

    /// Convert an address into a destination connection to forward traffic over
    pub async fn get_destination_connection(&self) -> Result<Connection, tokio::io::Error> {
        match self {
            Self::Tcp(tcp_addr) => {
                let socket = tokio::net::TcpStream::connect(tcp_addr).await?;
                Ok(Connection::Tcp(socket))
            }
            Self::Vsock(cid, port) => {
                let socket = tokio_vsock::VsockStream::connect(*cid, *port).await?;
                Ok(Connection::Vsock(socket))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Address;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_tcp_parse() {
        let parse_address = Address::new_tcp_address("127.0.0.1:443");
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert_eq!(parse_address.unwrap(), Address::Tcp(socket_addr));
    }

    #[test]
    fn test_vsock_parse() {
        let address = Address::new_vsock_address("3:8008");
        let vsock_addr = Address::Vsock(3, 8008);
        assert_eq!(vsock_addr, address.unwrap());

        let invalid_address = Address::new_vsock_address("3.14:0000");
        assert!(invalid_address.is_err());

        let too_many_tokens = Address::new_vsock_address("3:8008:9999:0000");
        assert!(too_many_tokens.is_err());
    }
}

#[pin_project::pin_project(project = EnumProj)]
/// Wrapper type to support both VSock and TCP as a generic connection type
pub enum Connection {
    Tcp(#[pin] tokio::net::TcpStream),
    Vsock(#[pin] tokio_vsock::VsockStream),
}

impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        match this {
            EnumProj::Tcp(conn) => conn.poll_read(cx, buf),
            EnumProj::Vsock(conn) => conn.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        match this {
            EnumProj::Tcp(conn) => conn.poll_write(cx, buf),
            EnumProj::Vsock(conn) => conn.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.project();
        match this {
            EnumProj::Tcp(conn) => conn.poll_flush(cx),
            EnumProj::Vsock(conn) => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let this = self.project();
        match this {
            EnumProj::Tcp(conn) => conn.poll_shutdown(cx),
            EnumProj::Vsock(conn) => conn.poll_shutdown(cx),
        }
    }
}

pub enum SourceConnection {
    Tcp(tokio::net::TcpListener),
    Vsock(tokio_vsock::VsockListener),
}

#[async_trait::async_trait]
pub trait Listener: Sized {
    type Connection: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin;
    type Error: std::fmt::Debug + std::fmt::Display;
    async fn accept(&mut self) -> Result<Self::Connection, Self::Error>;
}

#[async_trait::async_trait]
impl Listener for SourceConnection {
    type Connection = Connection;
    type Error = tokio::io::Error;

    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        match self {
            Self::Tcp(tcp_listener) => {
                let (accepted_conn, _socket) = tcp_listener.accept().await?;
                Ok(Connection::Tcp(accepted_conn))
            }
            Self::Vsock(vsock_listener) => {
                let (vsock_conn, _socket) = vsock_listener.accept().await?;
                Ok(Connection::Vsock(vsock_conn))
            }
        }
    }
}
