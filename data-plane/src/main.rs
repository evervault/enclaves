#[cfg(feature = "enclave")]
use data_plane::crypto::attest;
use data_plane::error::Result;

use data_plane::server::tls::TlsServerBuilder;
#[cfg(not(feature = "enclave"))]
use shared::server::tcp::TcpServer;
use shared::server::Listener;

#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpSocket;

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;

#[cfg(feature = "enclave")]
use shared::server::vsock::VsockServer;
use shared::utils::pipe_streams;

const CUSTOMER_CONNECT_PORT: u16 = 8008;
const DATA_PLANE_PORT: u16 = 7777;
#[cfg(feature = "enclave")]
const ENCLAVE_CID: u32 = 2021;

#[tokio::main]
async fn main() {
    println!("Data plane running.");
    start().await
}

#[cfg(not(feature = "network_egress"))]
async fn start() {
    println!("Running data plane with egress disabled");
    start_data_plane().await;
}

#[cfg(feature = "network_egress")]
async fn start() {
    println!("Running data plane with egress enabled");
    let _ = tokio::join!(
        start_data_plane(),
        EnclaveDns::bind_server(),
        EgressProxy::listen()
    );
}

async fn start_data_plane() {
    print!("Data plane starting on {}", DATA_PLANE_PORT);
    #[cfg(not(feature = "enclave"))]
    let get_server = TcpServer::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        DATA_PLANE_PORT,
    ))
    .await;

    #[cfg(feature = "enclave")]
    let get_server = VsockServer::bind(ENCLAVE_CID, DATA_PLANE_PORT.into()).await;

    let server = match get_server {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return;
        }
    };

    let tls_server_builder = TlsServerBuilder.with_server(server);
    let mut server = match tls_server_builder.with_self_signed_cert().await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return;
        }
    };

    loop {
        if let Ok(stream) = server.accept().await {
            tokio::spawn(handle_connection(stream));
        }
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite>(external_stream: S) -> Result<(u64, u64)> {
    let ip_addr = std::net::Ipv4Addr::new(0, 0, 0, 0);
    let tcp_socket = TcpSocket::new_v4()?;
    let customer_stream = tcp_socket
        .connect((ip_addr, CUSTOMER_CONNECT_PORT).into())
        .await?;

    let bytes_written = pipe_streams(external_stream, customer_stream).await?;
    Ok(bytes_written)
}
