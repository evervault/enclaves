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
pub const CLOUDFLARE_DNS_SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

pub fn read_dns_server_ip_from_env_var() -> Option<IpAddr> {
    std::env::var(DNS_SERVER_OVERRIDE_KEY)
        .ok()
        .and_then(|env_var| {
            env_var
                .parse()
                .map_err(|e| {
                    log::error!("Invalid IP provided to {DNS_SERVER_OVERRIDE_KEY}");
                    ServerError::InvalidIp(e)
                })
                .ok()
        })
}

pub struct DnsProxy {
    dns_server_ip: IpAddr,
}

impl DnsProxy {
    pub fn new(target_ip: IpAddr) -> Self {
        Self {
            dns_server_ip: target_ip,
        }
    }

    pub async fn listen(self) -> Result<()> {
        let mut server = get_vsock_server(DNS_PROXY_VSOCK_PORT, Parent).await?;

        let allowed_domains = shared::server::egress::get_egress_allow_list_from_env();
        loop {
            let domains = allowed_domains.clone();
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::proxy_dns_connection(self.dns_server_ip, stream, domains).await
                        {
                            log::error!("Error proxying dns connection: {e}");
                        }
                    });
                }
                Err(e) => log::error!("Error accepting connection in DNS proxy - {e:?}"),
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn remote_dns_socket(dns_server_ip: IpAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket_address = SocketAddr::new(dns_server_ip, 53);
        socket.connect(&socket_address).await?;
        Ok(socket)
    }

    async fn proxy_dns_connection<T: AsyncRead + AsyncWrite + Unpin>(
        target_ip: IpAddr,
        mut stream: T,
        allowed_domains: EgressDestinations,
    ) -> Result<()> {
        log::info!("Proxying request to remote");
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        let socket = Self::remote_dns_socket(target_ip).await?;
        let mut response_buffer = [0; 512];
        check_dns_allowed_for_domain(&request_buffer[..packet_size], allowed_domains.clone())?;
        socket.send(&request_buffer[..packet_size]).await?;
        let (amt, _) = socket.recv_from(&mut response_buffer).await?;
        let response_bytes = &response_buffer[..amt];
        cache_ip_for_allowlist(response_bytes)?;
        stream.write_all(response_bytes).await?;
        stream.flush().await?;
        Ok(())
    }
}

impl std::default::Default for DnsProxy {
    fn default() -> Self {
        Self {
            dns_server_ip: std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        }
    }
}
