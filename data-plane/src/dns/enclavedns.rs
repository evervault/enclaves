use super::error::DNSError;
use crate::dns::cache::Cache;
use bytes::Bytes;
use dns_message_parser::rr::A;
use dns_message_parser::Dns;
use shared::server::get_vsock_client;
use shared::server::CID::Parent;
use shared::DNS_PROXY_VSOCK_PORT;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

struct EnclaveDnsDriver {
    inner: Arc<UdpSocket>,
    dns_lookup_receiver: Receiver<(Bytes, SocketAddr)>,
    dns_request_upper_bound: std::time::Duration,
}

impl EnclaveDnsDriver {
    fn new(
        socket: Arc<UdpSocket>,
        dns_lookup_receiver: Receiver<(Bytes, SocketAddr)>,
        dns_request_upper_bound: std::time::Duration,
    ) -> Self {
        Self {
            inner: socket,
            dns_lookup_receiver,
            dns_request_upper_bound,
        }
    }

    async fn start_driver(mut self) {
        while let Some((dns_packet, src_addr)) = self.dns_lookup_receiver.recv().await {
            let dns_response = match self.perform_dns_lookup(dns_packet).await {
                Ok(dns_response) => dns_response,
                Err(e) => {
                    eprintln!("Failed to perform DNS Lookup: {e}");
                    continue;
                }
            };

            if let Err(e) = self.inner.send_to(&dns_response, &src_addr).await {
                eprintln!("Failed to send DNS Response: {e}");
            }
        }
    }

    /// Perform a DNS lookup using the proxy running on the Host, storing the resulting IPs in the Data-Plane's cache
    async fn perform_dns_lookup(&self, dns_packet: Bytes) -> Result<Bytes, DNSError> {
        // Attempt DNS lookup wth a 5 second timeout, flatten timeout errors into a DNS Error
        let dns_response = timeout(
            self.dns_request_upper_bound,
            Self::forward_dns_lookup(dns_packet),
        )
        .await??;

        let dns = Dns::decode(dns_response.clone())?;
        // No need to cache responses with no IPs, exit early
        if dns.answers.is_empty() {
            return Ok(dns_response);
        }

        let domain_name = dns
            .questions
            .get(0)
            .ok_or(DNSError::DNSNoQuestionsFound)?
            .domain_name
            .to_string();

        // Extract returned records from response
        let rr = dns
            .answers
            .iter()
            .filter_map(|rr| match rr {
                dns_message_parser::rr::RR::A(a) => Some(a.ipv4_addr.to_string()),
                _ => None,
            })
            .collect();

        Cache::store_ip(&domain_name, rr);

        Self::create_loopback_dns_response(dns)
    }

    /// Creates a spoofed DNS response which will cause the user process to request loopback
    /// instead of the IPs returned. The egressproxy will then forward the traffic out to the internet.
    fn create_loopback_dns_response(dns: Dns) -> Result<Bytes, DNSError> {
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
        Ok(serialized_dns_query.freeze())
    }

    /// Takes a DNS lookup as `Bytes` and sends forwards it over VSock to the host process to be sent to
    /// a public DNS Service
    async fn forward_dns_lookup(bytes: Bytes) -> Result<Bytes, DNSError> {
        let mut stream = get_vsock_client(DNS_PROXY_VSOCK_PORT, Parent).await?;
        stream.write_all(&bytes).await?;
        let mut buffer = [0; 512];
        let packet_size = stream.read(&mut buffer).await?;

        Ok(Bytes::copy_from_slice(&buffer[..packet_size]))
    }
}

/// Empty struct for the DNS proxy that runs in the data plane
pub struct EnclaveDnsProxy;

impl EnclaveDnsProxy {
    pub async fn bind_server() -> Result<(), DNSError> {
        println!("Starting DNS proxy");
        let socket = UdpSocket::bind("127.0.0.1:53").await?;
        let shared_socket = std::sync::Arc::new(socket);

        // Create a bounded sync channel to send DNS lookups between the Proxy and Driver
        let (dns_lookup_sender, dns_lookup_receiver) =
            tokio::sync::mpsc::channel::<(Bytes, SocketAddr)>(1000);

        let dns_driver_socket = shared_socket.clone();

        let dns_request_upper_bound = std::time::Duration::from_secs(5);
        let dns_driver = EnclaveDnsDriver::new(
            dns_driver_socket,
            dns_lookup_receiver,
            dns_request_upper_bound,
        );
        tokio::spawn(async move {
            println!("Starting DNS request driver");
            dns_driver.start_driver().await;
            eprintln!("Enclave DNS Driver exiting");
        });

        loop {
            let mut buffer = [0; 512];
            let (amt, src) = shared_socket.recv_from(&mut buffer).await?;
            let buf = Bytes::copy_from_slice(&buffer[..amt]);
            if let Err(e) = dns_lookup_sender.try_send((buf, src)) {
                eprintln!("Error dispatching DNS request in data plane: {e:?}");
            }
        }
    }
}
