use std::time::Duration;

use bytes::Bytes;
use shared::bridge::{Bridge, BridgeInterface, Direction};
use shared::{ENCLAVE_STATSD_PORT, STATS_VSOCK_PORT};
use tokio::net::UdpSocket;
use tokio::task;
use tokio::{io::AsyncWriteExt, time};

use crate::{error::Error, stats_client::StatsClient};

pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<(), Error> {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", ENCLAVE_STATSD_PORT)).await?;

        Self::record_system_metrics();
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
            if let Err(e) = Self::forward_stats(buf).await {
                log::error!("Error forwarding stats: {e}");
            }
            buffer.fill(0);
        }
    }

    async fn forward_stats(bytes: Bytes) -> Result<(), Error> {
        let mut stream =
            Bridge::get_client_connection(STATS_VSOCK_PORT, Direction::EnclaveToHost).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;

        Ok(())
    }

    fn record_system_metrics() {
        // Take interval in seconds from the SYSTEM_STATS_INTERVAL variable, defaulting to every minute.
        let interval = std::env::var("SYSTEM_STATS_INTERVAL")
            .ok()
            .and_then(|interval_str| interval_str.parse::<u64>().ok())
            .unwrap_or(60);

        task::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval));

            loop {
                interval.tick().await;
                StatsClient::record_system_metrics();
            }
        });
    }
}
