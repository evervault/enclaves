use shared::utils::pipe_streams;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

use crate::error::Result;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

#[cfg(feature = "network_egress")]
mod dnsproxy;
#[cfg(feature = "network_egress")]
mod egressproxy;

mod error;

const ENCLAVE_CONNECT_PORT: u16 = 7777;
const CONTROL_PLANE_PORT: u16 = 3031;

#[cfg(feature = "enclave")]
const ENCLAVE_CID: u32 = 2021;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting control plane on {}", CONTROL_PLANE_PORT);
    #[cfg(not(feature = "network_egress"))]
    if let Err(err) = tcp_server().await {
        eprintln!("Error running TCP server on host: {:?}", err);
    };

    #[cfg(feature = "network_egress")]
    let _ = tokio::join!(
        tcp_server(),
        dnsproxy::DnsProxy::listen(),
        egressproxy::EgressProxy::listen()
    );

    Ok(())
}

async fn tcp_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let tcp_listener = TcpListener::bind(addr).await?;

    loop {
        if let Ok((connection, _client_socket_addr)) = tcp_listener.accept().await {
            #[cfg(not(feature = "enclave"))]
            let enclave_stream = TcpStream::connect(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                ENCLAVE_CONNECT_PORT,
            ))
            .await?;

            #[cfg(feature = "enclave")]
            let enclave_stream =
                VsockStream::connect(ENCLAVE_CID, ENCLAVE_CONNECT_PORT.into()).await?;

            if let Err(e) = pipe_streams(connection, enclave_stream).await {
                eprintln!(
                    "An error occurred while piping the connection over vsock - {:?}",
                    e
                );
            }
        }
    }
}
