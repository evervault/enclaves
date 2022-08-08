use shared::utils::pipe_streams;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
use tokio::{io::AsyncWriteExt, net::TcpListener};

use crate::error::Result;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

mod e3proxy;
mod error;

#[cfg(feature = "enclave")]
const CONTROL_PLANE_PORT: u16 = 443;
#[cfg(not(feature = "enclave"))]
const CONTROL_PLANE_PORT: u16 = 3031;

#[cfg(feature = "enclave")]
use shared::ENCLAVE_CID;
use shared::ENCLAVE_CONNECT_PORT;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting control plane on {}", CONTROL_PLANE_PORT);
    let e3_proxy = e3proxy::E3Proxy::new();
    #[cfg(not(feature = "network_egress"))]
    {
        let (tcp_result, e3_result) = tokio::join!(tcp_server(), e3_proxy.listen());
        if let Err(err) = tcp_result {
            eprintln!("Error running TCP server on host: {:?}", err);
        };

        if let Err(err) = e3_result {
            eprintln!("Error running E3 proxy on host: {:?}", err);
        }
    }

    #[cfg(feature = "network_egress")]
    {
        let (tcp_result, dns_result, egress_result, e3_result) = tokio::join!(
            tcp_server(),
            control_plane::dnsproxy::DnsProxy::listen(),
            control_plane::egressproxy::EgressProxy::listen(),
            e3_proxy.listen()
        );

        if let Err(tcp_err) = tcp_result {
            eprintln!("An error occurred in the tcp server - {:?}", tcp_err);
        }

        if let Err(dns_err) = dns_result {
            eprintln!("An error occurred in the dns server - {:?}", dns_err);
        }

        if let Err(egress_err) = egress_result {
            eprintln!("An error occurred in the egress server - {:?}", egress_err);
        }

        if let Err(e3_err) = e3_result {
            eprintln!("An error occurred in the e3 server - {:?}", e3_err);
        }
    }

    Ok(())
}

#[cfg(not(feature = "enclave"))]
async fn get_connection_to_enclave() -> std::io::Result<TcpStream> {
    let ip_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    println!(
        "Connecting to tcp data plane on ({},{})",
        ip_addr, ENCLAVE_CONNECT_PORT
    );
    TcpStream::connect(std::net::SocketAddr::new(ip_addr, ENCLAVE_CONNECT_PORT)).await
}

#[cfg(feature = "enclave")]
async fn get_connection_to_enclave() -> std::io::Result<VsockStream> {
    println!(
        "Connecting to enclave on ({},{})",
        ENCLAVE_CID, ENCLAVE_CONNECT_PORT
    );
    VsockStream::connect(ENCLAVE_CID, ENCLAVE_CONNECT_PORT.into()).await
}

async fn tcp_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let tcp_listener = match TcpListener::bind(addr).await {
        Ok(tcp_listener) => tcp_listener,
        Err(e) => {
            eprintln!("Failed to bind to TCP Socket - {:?}", e);
            return Err(e.into());
        }
    };

    loop {
        if let Ok((mut connection, _client_socket_addr)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                println!("Accepted incoming TCP stream — {:?}", _client_socket_addr);
                let enclave_stream = match get_connection_to_enclave().await {
                    Ok(enclave_stream) => enclave_stream,
                    Err(e) => {
                        eprintln!(
                            "An error occurred while connecting to the enclave — {:?}",
                            e
                        );
                        connection
                            .shutdown()
                            .await
                            .expect("Failed to close connection to client");
                        return;
                    }
                };

                if let Err(e) = pipe_streams(connection, enclave_stream).await {
                    eprintln!(
                        "An error occurred while piping the connection over vsock - {:?}",
                        e
                    );
                }
            });
        }
    }
}
