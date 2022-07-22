use hyper::client::conn::handshake;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;

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
    tokio::spawn(http_server());

    #[cfg(feature = "network_egress")]
    let _ = tokio::join!(
        http_server(),
        dnsproxy::DnsProxy::listen(),
        egressproxy::EgressProxy::listen()
    );

    Ok(())
}

async fn http_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let service =
        make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(forward_to_enclave)) });
    let server = Server::bind(&addr).serve(service);
    server.await?;
    Ok(())
}

async fn forward_to_enclave(req: Request<Body>) -> Result<Response<Body>> {
    println!("Forwarding to enclave");
    #[cfg(not(feature = "enclave"))]
    let stream = TcpStream::connect(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        ENCLAVE_CONNECT_PORT,
    ))
    .await;

    #[cfg(feature = "enclave")]
    let stream = VsockStream::connect(ENCLAVE_CID, ENCLAVE_CONNECT_PORT.into()).await;

    let (mut request_sender, conn) = handshake(stream?).await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Error in connection to data plane: {}", e);
        }
    });

    let response = request_sender.send_request(req).await?;
    let (parts, body) = response.into_parts();

    Ok(Response::from_parts(parts, body))
}
