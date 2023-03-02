use super::error::DNSError;
use crate::dns::cache::Cache;
use bytes::{Bytes, BytesMut};
use dns_message_parser::rr::A;
use dns_message_parser::rr::RR;
use dns_message_parser::Dns;
use shared::server::get_vsock_client;
use shared::server::CID::Parent;
use shared::DNS_PROXY_VSOCK_PORT;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

pub struct EnclaveDns;

impl EnclaveDns {
    pub async fn bind_server() -> Result<(), DNSError> {
        println!("DNS proxy started");
        let socket = UdpSocket::bind("127.0.0.1:53").await?;

        loop {
            let mut buffer = [0; 512];
            let (amt, src) = socket.recv_from(&mut buffer).await?;
            let buf = Bytes::copy_from_slice(&buffer[..amt]);

            let dns_response = Self::forward_dns_lookup(buf.clone()).await?;
            let dns = Dns::decode(dns_response.clone())?;
            let domain_name = dns
                .questions
                .get(0)
                .ok_or(DNSError::DNSNoQuestionsFound)?
                .domain_name
                .to_string();
            let resource_records = dns.answers.clone();
            if resource_records.is_empty() {
                socket.send_to(&dns_response, &src).await?;
            } else {
                let rr = Self::get_records(resource_records);
                Cache::store_ip(&domain_name, rr);

                let local_response = Self::local_packet(dns.clone())?;
                socket.send_to(&local_response, &src).await?;
            }
        }
    }

    fn get_records(resource_records: Vec<RR>) -> Vec<String> {
        resource_records
            .into_iter()
            .filter_map(|rr| match rr {
                dns_message_parser::rr::RR::A(a) => Some(a.ipv4_addr.to_string()),
                _ => None,
            })
            .collect()
    }

    fn local_packet(dns: Dns) -> Result<BytesMut, DNSError> {
        let domain_name = dns
            .questions
            .get(0)
            .ok_or(DNSError::DNSNoQuestionsFound)?
            .domain_name
            .clone();

        let loopback = dns_message_parser::rr::RR::A(A {
            domain_name,
            ttl: u32::MAX,
            ipv4_addr: Ipv4Addr::new(127, 0, 0, 1),
        });

        let serialized_dns_query = Dns {
            id: dns.id,
            flags: dns.flags,
            questions: dns.questions,
            answers: vec![loopback],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode()?;
        Ok(serialized_dns_query)
    }

    async fn forward_dns_lookup(bytes: Bytes) -> Result<Bytes, DNSError> {
        let mut stream = get_vsock_client(DNS_PROXY_VSOCK_PORT, Parent).await?;
        stream.write_all(&bytes).await?;
        let mut buffer = [0; 512];
        let packet_size = stream.read(&mut buffer).await?;

        Ok(Bytes::copy_from_slice(&buffer[..packet_size]))
    }
}
