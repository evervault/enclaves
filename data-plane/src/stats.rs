use std::time::Duration;

use bytes::Bytes;
use shared::server::get_vsock_client;
use shared::server::CID::Parent;
use shared::{ENCLAVE_STATSD_PORT, STATS_VSOCK_PORT};
use tokio::net::UdpSocket;
use tokio::task;
use tokio::{io::AsyncWriteExt, time};

use crate::stats_client::StatsClient;

pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<(), std::io::Error> {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", ENCLAVE_STATSD_PORT)).await?;

        Self::record_system_metrics();
        let mut buffer = [0; 512];

        loop {
            let (amt, _) = match socket.recv_from(&mut buffer).await {
                Ok((amt, src)) => (amt, src),
                Err(e) => {
                    eprintln!("Error receiving stats: {e}");
                    buffer.fill(0);
                    continue;
                }
            };

            let buf = Bytes::copy_from_slice(&buffer[..amt]);
            if let Err(e) = Self::forward_stats(buf).await {
                eprintln!("Error forwarding stats: {e}");
            }
            buffer.fill(0);
        }
    }

    async fn forward_stats(bytes: Bytes) -> Result<(), std::io::Error> {
        let mut stream = get_vsock_client(STATS_VSOCK_PORT, Parent).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;

        Ok(())
    }

    fn record_system_metrics() {
        task::spawn(async {
            let mut interval = time::interval(Duration::from_secs(1));

            loop {
                interval.tick().await;
                StatsClient::record_system_metrics();
            }
        });
    }
}
