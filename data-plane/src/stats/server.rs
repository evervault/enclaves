use bytes::Bytes;
use shared::server::get_vsock_client;
use shared::stats::EXTERNAL_STATS_PROXY_ADDRESS;
use shared::ENCLAVE_STATSD_PORT;
use tokio::net::UdpSocket;
use tokio::io::AsyncWriteExt;

pub struct StatsProxy;

impl StatsProxy {
    pub async fn listen() -> Result<(), std::io::Error> {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", ENCLAVE_STATSD_PORT)).await?;

        let (external_vsock_port, cid) = EXTERNAL_STATS_PROXY_ADDRESS;
        let mut stream = get_vsock_client(external_vsock_port, cid)
            .await
            .unwrap();

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
