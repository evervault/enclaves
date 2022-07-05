use tokio::io::{AsyncRead,AsyncWrite};
use tokio::net::{TcpListener, TcpStream, TcpSocket};
use std::net::{SocketAddr, Ipv4Addr, IpAddr};

#[cfg(feature = "network_egress")]
mod enclavedns;

const CUSTOMER_CONNECT_PORT: u16 = 8008;
const DATA_PLANE_PORT: u16 = 7777;


#[tokio::main]
async fn main() {
    println!("Data plane running.");
    start().await
}

#[cfg(not(feature = "network_egress"))]
async fn start() {
    println!("Running data plane without egress enabled");
    start_data_plane().await;
}

#[cfg(feature = "network_egress")]
async fn start() {
    println!("Running data plane with egress enabled");
    tokio::join!(start_data_plane(), enclavedns::EnclaveDns::bind_server());
}

async fn start_data_plane() {
    print!("Data plane starting on {}", DATA_PLANE_PORT);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), DATA_PLANE_PORT);
    let listener = TcpListener::bind(addr).await.unwrap();

    while let Ok((stream, _address)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}

async fn handle_connection(external_stream: TcpStream) {
    let ip_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let tcp_socket = TcpSocket::new_v4().expect("Failed to create socket — socket sys call with AF_INET & SOCK_STREAM");
    let customer_stream = tcp_socket.connect((ip_addr, CUSTOMER_CONNECT_PORT).into()).await.expect("Failed to connect to customer service");

    match pipe_streams(external_stream, customer_stream).await {
        Ok(_) => println!("Finished piping connection to customer"),
        Err(e) => println!("{} | Error piping connection to customer ", e)
    };
}


async fn pipe_streams<T1, T2>(src: T1, dest: T2) -> Result<(u64, u64), tokio::io::Error>
where
    T1: AsyncRead + AsyncWrite,
    T2: AsyncRead + AsyncWrite
{
    let (mut src_reader, mut src_writer) = tokio::io::split(src);
    let (mut dest_reader, mut dest_writer) = tokio::io::split(dest);

    tokio::try_join!(
        tokio::io::copy(&mut src_reader, &mut dest_writer),
        tokio::io::copy(&mut dest_reader, &mut src_writer)
    )
}
