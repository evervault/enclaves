use crate::error::Result;
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    server::Listener,
};
use std::net::SocketAddr;
use std::ops::Deref;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;

pub struct StatsProxy;
impl StatsProxy {
    pub async fn spawn(port: u16, target_addrs: Vec<SocketAddr>) -> Result<()> {
        log::info!("Started control plane stats proxy");
        let mut server = Bridge::get_listener(port, Direction::HostToEnclave).await?;
        let target_addrs = std::sync::Arc::new(target_addrs);
        while !crate::health::is_draining() {
            match server.accept().await {
                Ok(stream) => {
                    let owned_addrs = target_addrs.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_connection(stream, owned_addrs).await {
                            log::warn!("Error proxying stats connection: {e}");
                        }
                    });
                }
                Err(e) => log::error!("Error accepting connection in stats proxy - {e:?}"),
            }
        }
        Ok(())
    }

    async fn proxy_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut stream: T,
        target_addrs: std::sync::Arc<Vec<SocketAddr>>,
    ) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut request_buffer = [0; 512];

        loop {
            let packet_size = stream.read(&mut request_buffer).await?;
            if packet_size == 0 {
                return Ok(());
            }
            for addr in target_addrs.deref() {
                if let Err(e) = socket.send_to(&request_buffer[..packet_size], addr).await {
                    log::error!(
                        "An error occurred while forwarding metrics to the remote server: {e}"
                    );
                }
            }
            request_buffer.fill(0);
        }
    }
}
