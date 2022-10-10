use crate::error::{Result, ServerError};
use shared::server::Listener;
#[cfg(not(feature = "enclave"))]
use shared::server::TcpServer;
#[cfg(feature = "enclave")]
use shared::server::VsockServer;
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
                    eprintln!("Invalid IP provided to {DNS_SERVER_OVERRIDE_KEY}");
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
        const DNS_LISTENING_PORT: u16 = 8585;
        #[cfg(not(feature = "enclave"))]
        let mut server = TcpServer::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            DNS_LISTENING_PORT,
        ))
        .await?;

        #[cfg(feature = "enclave")]
        let mut server = VsockServer::bind(shared::PARENT_CID, DNS_LISTENING_PORT.into()).await?;

        loop {
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_dns_connection(self.dns_server_ip, stream).await
                        {
                            eprintln!("Error proxying dns connection: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("Error accepting connection in DNS proxy - {:?}", e),
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
    ) -> Result<()> {
        println!("Proxying request to remote");
        let mut request_buffer = [0; 512];
        let packet_size = stream.read(&mut request_buffer).await?;

        let socket = Self::remote_dns_socket(target_ip).await?;
        let mut response_buffer = [0; 512];
        socket.send(&request_buffer[..packet_size]).await?;
        let (amt, _) = socket.recv_from(&mut response_buffer).await?;

        stream.write_all(&response_buffer[..amt]).await?;
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
