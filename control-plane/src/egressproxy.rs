use crate::error::Result;
use shared::rpc::request::ExternalRequest;
use shared::utils::pipe_streams;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct EgressProxy;

impl EgressProxy {
    pub async fn listen() {
        println!("Egress proxy started");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 4433);

        let server = match TcpListener::bind(addr).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("Error: {:?}", e);
                return;
            }
        };
        while let Ok((stream, _)) = server.accept().await {
            tokio::spawn(Self::handle_connection(stream));
        }
    }

    async fn handle_connection(mut external_stream: TcpStream) -> Result<(u64, u64)> {
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
