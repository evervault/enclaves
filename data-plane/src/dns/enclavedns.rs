use super::error::DNSError;
use bytes::Bytes;
use shared::server::egress::check_dns_allowed_for_domain;
use shared::server::egress::{cache_ip_for_allowlist, EgressDestinations};
use shared::server::get_vsock_client;
use shared::server::CID::Parent;
use shared::DNS_PROXY_VSOCK_PORT;
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
    pub async fn bind_server(allowed_destinations: EgressDestinations) -> Result<(), DNSError> {
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
            allowed_destinations,
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
    allowed_destinations: EgressDestinations,
}

impl EnclaveDnsDriver {
    fn new(
        socket: Arc<UdpSocket>,
        dns_lookup_receiver: Receiver<(Bytes, SocketAddr)>,
        dns_request_upper_bound: Duration,
        concurrency_limit: usize,
        allowed_destinations: EgressDestinations,
    ) -> Self {
        let concurrency_gate = Arc::new(Semaphore::new(concurrency_limit));
        Self {
            inner: socket,
            dns_lookup_receiver,
            dns_request_upper_bound,
            concurrency_gate,
            allowed_destinations,
        }
    }

    async fn start_driver(mut self) {
        while let Some((dns_packet, src_addr)) = self.dns_lookup_receiver.recv().await {
            let request_upper_bound = self.dns_request_upper_bound;
            let udp_socket = self.inner.clone();

            let permit = match self.concurrency_gate.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    log::error!("Failed to acquire permit from Semaphore, dropping lookup. {e:?}");
                    continue;
                }
            };
            let destinations = self.allowed_destinations.clone();
            // Create task per DNS lookup
            tokio::spawn(async move {
                // move permit into task to drop when lookup is complete
                let _lookup_permit = permit;
                let dns_response =
                    match Self::perform_dns_lookup(dns_packet, request_upper_bound, destinations)
                        .await
                    {
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

    /// Perform a DNS lookup using the proxy running on the Host
    async fn perform_dns_lookup(
        dns_packet: Bytes,
        request_upper_bound: Duration,
        allowed_destinations: EgressDestinations,
    ) -> Result<Bytes, DNSError> {
        // Check domain is allowed before proxying lookup
        check_dns_allowed_for_domain(&dns_packet.clone(), allowed_destinations)?;
        // Attempt DNS lookup wth a timeout, flatten timeout errors into a DNS Error
        let dns_response =
            timeout(request_upper_bound, Self::forward_dns_lookup(dns_packet)).await??;
        cache_ip_for_allowlist(&dns_response.clone())?;
        Ok(dns_response)
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
