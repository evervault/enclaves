use crate::e3_client::{create_connection_pool, self};
use crate::error::Result;
use crate::internal_dns;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::net::SocketAddr;
use std::ops::DerefMut;
#[cfg(not(feature = "enclave"))]
use tokio::io::AsyncWriteExt;
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

type AsyncDnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub struct E3Proxy {
    #[allow(unused)]
    dns_resolver: AsyncDnsResolver,
}

impl std::default::Default for E3Proxy {
    fn default() -> Self {
        Self::new()
    }
}

impl E3Proxy {
    pub fn new() -> Self {
        let dns_resolver = internal_dns::get_internal_dns_resolver()
            .expect("Failed to create internal dns resolver");
        Self { dns_resolver }
    }

    #[cfg(feature = "enclave")]
    async fn shutdown_conn(connection: tokio_vsock::VsockStream) {
        if let Err(e) = connection.shutdown(std::net::Shutdown::Both) {
            eprintln!("Failed to shutdown data plane connection — {e:?}");
        }
    }

    #[cfg(not(feature = "enclave"))]
    async fn shutdown_conn(mut connection: tokio::net::TcpStream) {
        if let Err(e) = connection.shutdown().await {
            eprintln!("Failed to shutdown data plane connection — {e:?}");
        }
    }


    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CRYPTO_PORT, Parent).await?;
        let e3_pool = create_connection_pool(3);

        println!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);

        let e3_conn = e3_pool.get().await.unwrap().deref_mut();
        loop {
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    panic!("Error accepting crypto request — {e:?}");
                    // continue;
                }
            };
            println!("Crypto request received");

            tokio::spawn(async move {                
                if let Err(e) = shared::utils::pipe_streams(connection, e3_conn).await {
                    eprintln!("Error streaming from Data Plane to e3 — {e:?}");
                }
             });
        }

        #[allow(unreachable_code)]
        Ok(())
    }

    #[cfg(feature = "enclave")]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        internal_dns::get_ip_for_host_with_dns_resolver(
            &self.dns_resolver,
            "e3.cages-e3.internal.",
            443,
        )
        .await
    }

    // supporting local env
    #[cfg(not(feature = "enclave"))]
    async fn get_ip_for_e3(&self) -> Result<Option<SocketAddr>> {
        internal_dns::get_ip_for_localhost(7676)
    }
}
