use crate::error::{Result, ServerError};
use shared::server::egress::check_dns_allowed_for_domain;
use shared::server::egress::{cache_ip_for_allowlist, EgressDestinations};
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use shared::DNS_PROXY_VSOCK_PORT;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

const DNS_SERVER_OVERRIDE_KEY: &str = "EV_CONTROL_PLANE_DNS_SERVER";

lazy_static::lazy_static! {
  pub static ref CLOUDFLARE_DNS_SERVERS: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))];
  pub static ref GOOGLE_DNS_SERVERS: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))];
  pub static ref OPEN_DNS_SERVERS: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220))];
}

pub fn read_dns_server_ips_from_env_var() -> Option<Vec<IpAddr>> {
    std::env::var(DNS_SERVER_OVERRIDE_KEY).ok().map(|env_var| {
        env_var
            .split(',')
            .filter_map(|dns_addr| dns_addr.parse::<IpAddr>().ok())
            .collect()
    })
}

pub struct DnsProxy {
    dns_server_ips: Vec<IpAddr>,
}

impl std::default::Default for DnsProxy {
    fn default() -> Self {
        Self {
            dns_server_ips: [
                CLOUDFLARE_DNS_SERVERS.as_slice(),
                GOOGLE_DNS_SERVERS.as_slice(),
            ]
            .concat(),
        }
    }
}

impl DnsProxy {
    pub fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            dns_server_ips: ips,
        }
    }

    pub async fn listen(self) -> Result<()> {
        let mut server = get_vsock_server(DNS_PROXY_VSOCK_PORT, Parent).await?;

        let allowed_domains = shared::server::egress::get_egress_allow_list_from_env();
        loop {
            let domains = allowed_domains.clone();
            match server.accept().await {
                Ok(mut stream) => {
                    let dns_services = self.dns_server_ips.clone();
                    tokio::spawn(async move {
                        for dns_service in dns_services.iter() {
                            let dns_req_timing = std::time::Instant::now();
                            let dns_lookup =
                                Self::proxy_dns_connection(dns_service, &mut stream, &domains)
                                    .await;
                            let elapsed = std::time::Instant::now()
                                .duration_since(dns_req_timing)
                                .as_millis();
                            match dns_lookup {
                                Ok(_) => {
                                  log::info!("DNS Resolved successfully after: {elapsed}ms");
                                  return;
                                },
                                Err(ServerError::EgressError(e)) => {
                                    log::error!("DNS Connection to {dns_service} rejected with egress error: {e}");
                                    return;
                                }
                                Err(e) => log::error!(
                                    "Error proxying dns connection to {dns_service}: {e}. Elapsed: {elapsed}ms"
                                ),
                            }
                        }
                    });
                }
                Err(e) => log::error!("Error accepting connection in DNS proxy - {e:?}"),
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn remote_dns_socket(dns_server_ip: &IpAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket_address = SocketAddr::new(*dns_server_ip, 53);
        socket.connect(&socket_address).await?;
        Ok(socket)
    }

    async fn proxy_dns_connection<T: AsyncRead + AsyncWrite + Unpin>(
        target_ip: &IpAddr,
        stream: &mut T,
        allowed_domains: &EgressDestinations,
    ) -> Result<()> {
        log::info!("Proxying request to remote: {target_ip}");
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        let socket = Self::remote_dns_socket(target_ip).await?;
        let mut response_buffer = [0; 512];
        check_dns_allowed_for_domain(&request_buffer[..packet_size], allowed_domains)?;
        socket.send(&request_buffer[..packet_size]).await?;
        let (amt, _) = socket.recv_from(&mut response_buffer).await?;
        let response_bytes = &response_buffer[..amt];
        cache_ip_for_allowlist(response_bytes)?;
        stream.write_all(response_bytes).await?;
        stream.flush().await?;
        Ok(())
    }
}
