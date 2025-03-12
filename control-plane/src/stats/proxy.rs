use crate::error::Result;
use shared::server::{get_vsock_server, Listener, CID};
use std::net::SocketAddr;
use std::ops::Deref;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

pub struct StatsProxy;
impl StatsProxy {
    pub async fn spawn((port, cid): (u16, CID), target_addrs: Vec<SocketAddr>) -> Result<()> {
        log::info!("Started control plane stats proxy");
        let mut server = get_vsock_server(port, cid).await?;
        let target_addrs = std::sync::Arc::new(target_addrs);
        loop {
            match server.accept().await {
                Ok(stream) => {
                    let owned_addrs = target_addrs.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_connection(stream, owned_addrs).await {
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
    
    async fn proxy_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut stream: T,
        target_addrs: std::sync::Arc<Vec<SocketAddr>>,
    ) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        for addr in target_addrs.deref() {
            if let Err(e) = socket.send_to(&request_buffer[..packet_size], addr).await {
                log::error!("An error occurred while forwarding metrics to the remote server: {e}");
            }
        }

        stream.flush().await?;
        Ok(())
    }
}
