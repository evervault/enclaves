use crate::configuration::get_external_metrics_enabled;
use crate::error::Result;
use shared::STATS_VSOCK_PORT;
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    server::Listener,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

const CLOUDWATCH_STATSD_PORT: u16 = 8125;
const EXTERNAL_STATSD_PORT: u16 = 8126;
pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<()> {
        log::info!("Started control plane stats proxy");
        let external_metrics_enabled = get_external_metrics_enabled();
        let mut server = Bridge::get_listener(STATS_VSOCK_PORT, Direction::HostToEnclave).await?;

        loop {
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::proxy_connection(stream, external_metrics_enabled).await
                        {
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

    async fn remote_socket(dns_server_ip: IpAddr, port: u16) -> Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket_address = SocketAddr::new(dns_server_ip, port);
        socket.connect(&socket_address).await?;
        Ok(socket)
    }

    async fn proxy_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut stream: T,
        external_metrics_enabled: bool,
    ) -> Result<()> {
        #[cfg(not(feature = "enclave"))]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(172, 20, 0, 6));
        #[cfg(feature = "enclave")]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        if external_metrics_enabled {
            let (cloudwatch, external_metric) = tokio::join!(
                Self::send_metrics(
                    target_ip,
                    CLOUDWATCH_STATSD_PORT,
                    &request_buffer[..packet_size]
                ),
                Self::send_metrics(
                    target_ip,
                    EXTERNAL_STATSD_PORT,
                    &request_buffer[..packet_size]
                )
            );
            if let Err(e) = cloudwatch {
                log::error!("Error sending metrics to remote server: {e}");
            }
            if let Err(e) = external_metric {
                log::error!("Error sending metrics to external server: {e}");
            }
        } else {
            Self::send_metrics(
                target_ip,
                CLOUDWATCH_STATSD_PORT,
                &request_buffer[..packet_size],
            )
            .await?;
        }

        stream.flush().await?;
        Ok(())
    }

    async fn send_metrics(target_ip: IpAddr, port: u16, stats_buffer: &[u8]) -> Result<()> {
        let socket = Self::remote_socket(target_ip, port).await?;
        socket.send(stats_buffer).await?;
        Ok(())
    }
}
