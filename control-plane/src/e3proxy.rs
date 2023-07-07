use crate::e3_client::E3Client;
use crate::error::Result;
use crate::internal_dns;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
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

    pub async fn listen(self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CRYPTO_PORT, Parent).await?;
        let e3_client = E3Client::new();

        println!("Running e3 proxy on {}", shared::ENCLAVE_CRYPTO_PORT);
        loop {
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting crypto request — {e:?}");
                    continue;
                }
            };
            println!("Crypto request received");

            let e3_stream = e3_client.new_conn().await.unwrap();

            tokio::spawn(async move {
                if let Err(e) = shared::utils::pipe_streams(connection, e3_stream).await {
                    eprintln!("Error streaming from Data Plane to e3 — {e:?}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}
