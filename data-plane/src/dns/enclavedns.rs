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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc::Receiver, Semaphore};
use tokio::time::timeout;

/// Empty struct for the DNS proxy that runs in the data plane
pub struct EnclaveDnsProxy;

impl EnclaveDnsProxy {
    pub async fn bind_server() -> Result<(), DNSError> {
        log::info!("Starting DNS proxy");
        let socket = UdpSocket::bind("127.0.0.1:53").await?;
        let shared_socket = std::sync::Arc::new(socket);
        let dns_dispatch_timeout = std::time::Duration::from_secs(1);

        let max_concurrent_requests = 250;
        // Create a bounded sync channel to send DNS lookups between the Proxy and Driver
        let (dns_lookup_sender, dns_lookup_receiver) =
            tokio::sync::mpsc::channel::<(Bytes, SocketAddr)>(500);

        let dns_driver_socket = shared_socket.clone();

        let dns_request_upper_bound = std::time::Duration::from_secs(3);
        let dns_driver = EnclaveDnsDriver::new(
            dns_driver_socket,
            dns_lookup_receiver,
            dns_request_upper_bound,
            max_concurrent_requests,
        );
        tokio::spawn(async move {
            log::info!("Starting DNS request driver");
            dns_driver.start_driver().await;
            log::info!("Enclave DNS Driver exiting");
        });

        loop {
            let mut buffer = [0; 512];
            let (amt, src) = shared_socket.recv_from(&mut buffer).await?;
            let buf = Bytes::copy_from_slice(&buffer[..amt]);
            let dispatch_result =
                timeout(dns_dispatch_timeout, dns_lookup_sender.send((buf, src))).await;

            match dispatch_result {
                Ok(Err(e)) => log::error!("Error dispatching DNS request: {e:?}"),
                Err(e) => log::error!("Timeout dispatching DNS request: {e:?}"),
                _ => {}
            };
        }
    }
}

struct EnclaveDnsDriver {
    inner: Arc<UdpSocket>,
    dns_lookup_receiver: Receiver<(Bytes, SocketAddr)>,
    dns_request_upper_bound: Duration,
    concurrency_gate: Arc<Semaphore>,
}

impl EnclaveDnsDriver {
    fn new(
        socket: Arc<UdpSocket>,
        dns_lookup_receiver: Receiver<(Bytes, SocketAddr)>,
        dns_request_upper_bound: Duration,
        concurrency_limit: usize,
    ) -> Self {
        let concurrency_gate = Arc::new(Semaphore::new(concurrency_limit));
        Self {
            inner: socket,
            dns_lookup_receiver,
            dns_request_upper_bound,
            concurrency_gate,
        }
    }

    async fn start_driver(mut self) {
        while let Some((dns_packet, src_addr)) = self.dns_lookup_receiver.recv().await {
            let request_upper_bound = self.dns_request_upper_bound.clone();
            let udp_socket = self.inner.clone();

            let permit = match self.concurrency_gate.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    log::error!("Failed to acquire permit from Semaphore, dropping lookup. {e:?}");
                    continue;
                }
            };

            // Create task per DNS lookup
            tokio::spawn(async move {
                // move permit into task to drop when lookup is complete
                let _lookup_permit = permit;
                let dns_response =
                    match Self::perform_dns_lookup(dns_packet, request_upper_bound).await {
                        Ok(dns_response) => dns_response,
                        Err(e) => {
                            log::error!("Failed to perform DNS Lookup: {e}");
                            return;
                        }
                    };

                if let Err(e) = udp_socket.send_to(&dns_response, &src_addr).await {
                    log::error!("Failed to send DNS Response: {e}");
                }
            });
        }
    }

    /// Perform a DNS lookup using the proxy running on the Host, storing the resulting IPs in the Data-Plane's cache
    async fn perform_dns_lookup(
        dns_packet: Bytes,
        request_upper_bound: Duration,
    ) -> Result<Bytes, DNSError> {
        // Attempt DNS lookup wth a timeout, flatten timeout errors into a DNS Error
        let dns_response =
            timeout(request_upper_bound, Self::forward_dns_lookup(dns_packet)).await??;

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

#[cfg(test)]
mod test {
    use super::*;

    fn generate_dummy_dns_response(
        answer_ip: std::net::Ipv4Addr,
        domain_name: dns_message_parser::DomainName,
    ) -> Dns {
        Dns {
            id: 0,
            flags: dns_message_parser::Flags {
                qr: true,
                opcode: dns_message_parser::Opcode::Query,
                aa: true,
                tc: true,
                rd: true,
                ra: true,
                ad: true,
                cd: true,
                rcode: dns_message_parser::RCode::NoError,
            },
            questions: vec![dns_message_parser::question::Question {
                domain_name: domain_name.clone(),
                q_class: dns_message_parser::question::QClass::ANY,
                q_type: dns_message_parser::question::QType::A,
            }],
            answers: vec![dns_message_parser::rr::RR::A(dns_message_parser::rr::A {
                domain_name,
                ttl: 60,
                ipv4_addr: answer_ip,
            })],
            authorities: vec![],
            additionals: vec![],
        }
    }

    #[test]
    fn test_loopback_dns_responses() {
        let mut dummy_domain_name = dns_message_parser::DomainName::default();
        dummy_domain_name.append_label("acme").unwrap();
        dummy_domain_name.append_label("org").unwrap();
        let dummy_ip_answer = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let dummy_dns_response =
            generate_dummy_dns_response(dummy_ip_answer.clone(), dummy_domain_name.clone());

        let loopback_dns_response =
            EnclaveDnsDriver::create_loopback_dns_response(dummy_dns_response).unwrap();
        let decoded_dns = Dns::decode(loopback_dns_response).unwrap();
        let loopback_dns_answer = decoded_dns.answers.first().unwrap();
        let dns_message_parser::rr::RR::A(a_record) = loopback_dns_answer else {
            panic!("create_loopback_dns_response changed DNS record type");
        };
        assert_ne!(a_record.ipv4_addr, dummy_ip_answer);
        assert_eq!(a_record.ipv4_addr, std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(a_record.domain_name, dummy_domain_name);
    }
}
