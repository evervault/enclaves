#[cfg(not(feature = "enclave"))]
pub type Connection = tokio::net::TcpStream;

#[cfg(feature = "enclave")]
pub type Connection = tokio_vsock::VsockStream;

#[cfg(not(feature = "enclave"))]
pub async fn get_socket(port: u16) -> Result<Connection, tokio::io::Error> {
    Connection::connect(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        port,
    ))
    .await
}

#[cfg(feature = "enclave")]
pub async fn get_socket(port: u16) -> Result<Connection, tokio::io::Error> {
    Connection::connect(shared::PARENT_CID, port.into()).await
}
