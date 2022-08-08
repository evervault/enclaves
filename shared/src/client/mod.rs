#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

#[cfg(feature = "enclave")]
pub async fn get_client_socket(port: u16) -> std::io::Result<VsockStream> {
    VsockStream::connect(crate::ENCLAVE_CID, port.into()).await
}

#[cfg(not(feature = "enclave"))]
pub async fn get_client_socket(port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect((
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        port,
    ))
    .await
}
