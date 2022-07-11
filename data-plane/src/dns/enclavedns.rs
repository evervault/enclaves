use bytes::{Bytes, BytesMut};
use dns_message_parser::rr::A;
use dns_message_parser::rr::RR;
use dns_message_parser::{Dns, EncodeError};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use ttl_cache::TtlCache;

use super::error::DNSError;

pub struct EnclaveDns;

impl EnclaveDns {
    pub async fn bind_server() -> Result<(), DNSError> {
        let mut cache: TtlCache<String, Vec<RR>> = TtlCache::new(10);

        let socket = UdpSocket::bind("127.0.0.1:5300").await?;

        loop {
            let mut buffer = [0; 512];
            let (amt, src) = socket.recv_from(&mut buffer).await?;
            let buf = Bytes::copy_from_slice(&buffer[..amt]);

            let dns_response = Self::forward_dns_lookup(buf.clone()).await?;
            let dns = Dns::decode(dns_response.clone())?;
            let domain_name = dns.questions.get(0).unwrap().domain_name.to_string();
            let resource_records = dns.answers.clone();
            if resource_records.is_empty() {
                socket.send_to(&dns_response, &src).await?;
            } else {
                cache.insert(
                    domain_name.clone(),
                    resource_records,
                    Duration::from_secs(30),
                );
                let local_response = Self::local_packet(dns.clone())?;
                socket.send_to(&local_response, &src).await?;
            }
        }
    }

    async fn get_listener() -> Result<TcpStream, tokio::io::Error> {
        TcpStream::connect(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            8585,
        ))
        .await
    }

    fn local_packet(dns: Dns) -> Result<BytesMut, EncodeError> {
        let domain_name = dns.questions.get(0).unwrap().domain_name.clone();

        let loopback = dns_message_parser::rr::RR::A(A {
            domain_name,
            ttl: u32::MAX,
            ipv4_addr: Ipv4Addr::new(127, 0, 0, 1),
        });

        Dns {
            id: dns.id,
            flags: dns.flags,
            questions: dns.questions,
            answers: vec![loopback],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode()
    }

    async fn forward_dns_lookup(bytes: Bytes) -> Result<Bytes, DNSError> {
        let mut stream = Self::get_listener().await?;
        stream.write_all(&bytes).await?;
        let mut buffer = [0; 512];
        let packet_size = stream.read(&mut buffer).await?;
        Ok(Bytes::copy_from_slice(&buffer[..packet_size]))
    }
}
