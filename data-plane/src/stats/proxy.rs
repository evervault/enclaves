use bytes::Bytes;
use shared::bridge::{Bridge, BridgeInterface, Direction};
use shared::EXTERNAL_STATS_BRIDGE_PORT;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<(), shared::server::error::ServerError> {
        let socket = UdpSocket::bind("127.0.0.1:8125").await?;

        let mut stream =
            Bridge::get_client_connection(EXTERNAL_STATS_BRIDGE_PORT, Direction::EnclaveToHost)
                .await?;

        let mut buffer = [0; 512];
        loop {
            let (amt, _) = match socket.recv_from(&mut buffer).await {
                Ok((amt, src)) => (amt, src),
                Err(e) => {
                    log::error!("Error receiving stats: {e}");
                    buffer.fill(0);
                    continue;
                }
            };

            let buf = Bytes::copy_from_slice(&buffer[..amt]);
            let _ = stream.write_all(&buf).await;
            let _ = stream.flush().await;
            buffer.fill(0);
        }
    }
}
