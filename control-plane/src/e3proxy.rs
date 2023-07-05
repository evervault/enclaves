use crate::e3_client::create_connection_pool;
use crate::error::Result;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::ops::DerefMut;
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
        let e3_pool = match create_connection_pool(3) {
            Ok(pool) => pool,
            Err(e) => return Err(e)
        }; 

        println!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);

        loop {
            let mut e3_conn = e3_pool.get().await.unwrap();

            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting crypto request — {e:?}");
                    continue;
                }
            };
            println!("Crypto request received");

            tokio::spawn(async move {
                if let Err(e) =
                    shared::utils::pipe_streams(connection, &mut e3_conn.deref_mut().inner).await
                {
                    eprintln!("Error streaming from Data Plane to e3 — {e:?}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}
