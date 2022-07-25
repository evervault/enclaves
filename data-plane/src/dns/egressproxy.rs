use crate::dns::error::DNSError::MissingIP;
use shared::server::tcp::TcpServer;
use shared::server::Listener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use super::error::DNSError;
use crate::dns::cache::Cache;
use shared::rpc::request::ExternalRequest;
use shared::utils::pipe_streams;

pub struct EgressProxy;

impl EgressProxy {
    pub async fn listen() {
        println!("Egress proxy started");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 443);

        let mut server = match TcpServer::bind(addr).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("Error: {:?}", e);
                return;
            }
        };
        while let Ok(stream) = server.accept().await {
            tokio::spawn(Self::handle_egress_connection(stream));
        }
    }

    fn get_hostname(data: Vec<u8>) -> Option<String> {
        let (_, parsed_request) = parse_tls_plaintext(&data).unwrap();

        let client_hello = match &parsed_request.msg[0] {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => client_hello,
            _ => return None,
        };

        let raw_extensions = match client_hello.ext {
            Some(raw_extensions) => raw_extensions,
            _ => return None,
        };
        let mut destination = "".to_string();
        let (_, extensions) = parse_tls_extensions(raw_extensions).unwrap();

        for extension in extensions {
            if let TlsExtension::SNI(sni_vec) = extension {
                for (_, item) in sni_vec {
                    if let Ok(hostname) = std::str::from_utf8(item) {
                        destination = hostname.to_string();
                    }
                }
            }
        }
        Some(destination)
    }

    async fn handle_egress_connection(mut external_stream: TcpStream) -> Result<(), DNSError> {
        println!("Forwarding over 443");

        let mut buf = vec![0u8; 4096];
        let ip_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let tcp_socket = TcpSocket::new_v4()?;

        let n = external_stream.read(&mut buf).await?;
        let customer_data = &mut buf[..n];

        let hostname = Self::get_hostname(customer_data.to_vec()).unwrap();

        let ip: Option<String> = Cache::get_ip(hostname.clone())
            .and_then(|ips| ips.get(0).map(|first| first.to_string()));

        match ip {
            Some(remote_ip) => {
                let mut data_plane_stream = tcp_socket.connect((ip_addr, 4433).into()).await?;

                let external_request = ExternalRequest {
                    ip: remote_ip.to_string(),
                    data: customer_data.to_vec(),
                }
                .to_bytes()?;

                data_plane_stream.write_all(&external_request).await?;

                pipe_streams(external_stream, data_plane_stream).await?;
                Ok(())
            }
            None => Err(MissingIP(format!(
                "Couldn't find cached ip for {}",
                hostname.clone()
            ))),
        }
    }
}
