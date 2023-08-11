#[cfg(feature = "enclave")]
use shared::ENCLAVE_CID;
#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

#[cfg(not(feature = "enclave"))]
pub async fn get_connection_to_enclave(port: u16) -> std::io::Result<TcpStream> {
    let ip_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    log::debug!("Connecting to tcp data plane on ({ip_addr},{port})");
    TcpStream::connect(std::net::SocketAddr::new(ip_addr, port)).await
}

#[cfg(feature = "enclave")]
pub async fn get_connection_to_enclave(port: u16) -> std::io::Result<VsockStream> {
    VsockStream::connect(ENCLAVE_CID, port.into()).await
}
