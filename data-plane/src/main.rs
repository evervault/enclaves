#[cfg(feature = "tls")]
use data_plane::error::Error;
use data_plane::server::Listener;
#[cfg(not(feature = "enclave"))]
use data_plane::server::TcpServer;
#[cfg(feature = "tls")]
use data_plane::server::TlsServer;

#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpSocket;

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;

#[cfg(feature = "enclave")]
use data_plane::server::VsockServer;
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

    #[cfg(not(feature = "tls"))]
    let mut server = server;

    #[cfg(feature = "tls")]
    let mut server = {
        println!("TLS enabled");
        match enable_tls(server).await {
            Ok(tls_server) => tls_server,
            Err(e) => {
                eprintln!("Error: {:?}", e);
                return;
            }
        }
    };

    while let Ok(stream) = server.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}

#[cfg(all(feature = "tls", feature = "local-cert"))]
async fn enable_tls(server: TcpServer) -> Result<TlsServer, Error> {
    println!("--> Using local cert + key");
    let tls_builder = TlsServer::builder().with_tcp_server(server);
    let tls_server = tls_builder.with_local_cert().await?;
    Ok(tls_server)
}

#[cfg(all(feature = "tls", not(feature = "local-cert")))]
async fn enable_tls(server: TcpServer) -> Result<TlsServer, Error> {
    println!("--> Using remote cert + key");
    let tls_builder = TlsServer::builder().with_tcp_server(server);
    let tls_server = tls_builder.with_remote_cert().await?;
    Ok(tls_server)
}

async fn handle_connection<S: AsyncRead + AsyncWrite>(
    external_stream: S,
) -> Result<(u64, u64), std::io::Error> {
    let ip_addr = std::net::Ipv4Addr::new(0, 0, 0, 0);
    let tcp_socket = TcpSocket::new_v4()?;
    let customer_stream = tcp_socket
        .connect((ip_addr, CUSTOMER_CONNECT_PORT).into())
        .await?;

    pipe_streams(external_stream, customer_stream).await
}
