use crate::error::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

pub struct DnsProxy;

impl DnsProxy {
    pub async fn listen() -> Result<()> {
        const DNS_LISTENING_PORT: u16 = 8585;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), DNS_LISTENING_PORT);
        let listener = TcpListener::bind(addr).await?;

        while let Ok((stream, _address)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = Self::proxy_dns_connection(stream).await {
                    eprintln!("Error proxying dns connection: {}", e);
                }
            });
        }
        Ok(())
    }

    async fn remote_dns_socket() -> Result<UdpSocket> {
        let local_address = "0.0.0.0:5683";
        let socket = UdpSocket::bind(local_address).await?;
        let socket_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        socket.connect(&socket_address).await?;
        Ok(socket)
    }

    async fn proxy_dns_connection(mut stream: TcpStream) -> Result<()> {
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        let socket = Self::remote_dns_socket().await?;
        let mut response_buffer = [0; 512];
        socket.send(&request_buffer[..packet_size]).await?;
        let (amt, _) = socket.recv_from(&mut response_buffer).await?;

        stream.write_all(&response_buffer[..amt]).await?;
        stream.flush().await?;
        Ok(())
    }
}
