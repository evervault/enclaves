use crate::e3_client::E3Client;
use crate::error::Result;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
#[allow(unused)]
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;

pub struct E3Proxy;

impl std::default::Default for E3Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Proxy {
    pub fn new() -> Self {
        Self
    }

    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CRYPTO_PORT, Parent).await?;
        let e3_client = E3Client::new();

        println!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);

        loop {
            let e3_conn = e3_client.new_conn().await?;
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting crypto request — {e:?}");
                    continue;
                }
            };
            println!("Crypto request received");

            println!("{e3_conn:?}");

            tokio::spawn(async move {
                if let Err(e) = shared::utils::pipe_streams(connection, e3_conn).await {
                    eprintln!("Error streaming from Data Plane to e3 — {e:?}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}
