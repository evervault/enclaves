use crate::error::Result;
use shared::rpc::request::ExternalRequest;
#[cfg(not(feature = "enclave"))]
use shared::server::tcp::TcpServer;
#[cfg(feature = "enclave")]
use shared::server::vsock::VsockServer;
use shared::server::Listener;
use shared::utils::pipe_streams;
#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct EgressProxy;

#[cfg(feature = "enclave")]
const PARENT_CID: u32 = 3;
#[cfg(feature = "enclave")]
const PROXY_PORT: u32 = 4433;

impl EgressProxy {
    pub async fn listen() -> Result<()> {
        println!("Egress proxy started");

        #[cfg(not(feature = "enclave"))]
        let mut server =
            TcpServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4433)).await?;

        #[cfg(feature = "enclave")]
        let mut server = VsockServer::bind(shared::PARENT_CID, PROXY_PORT).await?;

        loop {
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream).await {
                            eprintln!(
                                "An error occurred while handling an egress connection - {:?}",
                                e
                            );
                        }
                    });
                }
                Err(e) => {
                    eprintln!(
                        "An error occurred accepting the egress connection — {:?}",
                        e
                    );
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn handle_connection<T: AsyncReadExt + AsyncWriteExt + Unpin>(
        mut external_stream: T,
    ) -> Result<(u64, u64)> {
        println!("Recieved request to egress proxy");
        let mut request_buffer = [0; 4096];
        let packet_size = external_stream.read(&mut request_buffer).await?;
        let req = &request_buffer[..packet_size];
        let external_request = ExternalRequest::from_bytes(req.to_vec())?;

        let connect_ip = format!("{}:443", external_request.ip);

        let mut remote_stream = TcpStream::connect(connect_ip).await?;
        remote_stream.write_all(&external_request.data).await?;

        let joined_streams = pipe_streams(external_stream, remote_stream).await?;
        Ok(joined_streams)
    }
}
