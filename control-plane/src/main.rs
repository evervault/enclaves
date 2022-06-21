use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use tokio::net::TcpStream;
use hyper::client::conn::handshake;

const ENCLAVE_CONNECT_PORT: u16 = 7777;
const CONTROL_PLANE_PORT: u16 = 3030;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), CONTROL_PLANE_PORT);

    let service = make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(forward_to_enclave)) });
    let server = Server::bind(&addr).serve(service);

    println!("Control plane listening on http://{}", addr);

    server.await?;

    Ok(())
}


async fn forward_to_enclave(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {

    let stream = TcpStream::connect(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        ENCLAVE_CONNECT_PORT,
    )).await;


    let (mut request_sender, conn) = handshake(stream.unwrap()).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Error in connection to data plane: {}", e);
        }
    });

    let response = request_sender.send_request(req).await.unwrap(); 
    let (parts, body) = response.into_parts();

    Ok(Response::from_parts(parts, body))
}