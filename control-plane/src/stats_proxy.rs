use crate::error::Result;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use shared::STATS_VSOCK_PORT;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<()> {
        log::info!("Started control plane stats proxy");
        let mut server = get_vsock_server(STATS_VSOCK_PORT, Parent).await?;

        loop {
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_connection(stream).await {
                            log::error!("Error proxying stats connection: {e}");
                        }
                    });
                }
                Err(e) => log::error!("Error accepting connection in stats proxy - {e:?}"),
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn remote_socket(dns_server_ip: IpAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket_address = SocketAddr::new(dns_server_ip, 8125);
        socket.connect(&socket_address).await?;
        Ok(socket)
    }

    async fn proxy_connection<T: AsyncRead + AsyncWrite + Unpin>(mut stream: T) -> Result<()> {
        #[cfg(not(feature = "enclave"))]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(172, 20, 0, 6));
        #[cfg(feature = "enclave")]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        let socket = Self::remote_socket(target_ip).await?;
        socket.send(&request_buffer[..packet_size]).await?;
        stream.flush().await?;
        Ok(())
    }
}
