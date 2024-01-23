use super::error::DNSError;
use crate::FeatureContext;
use shared::rpc::request::ExternalRequest;
use shared::server::egress::check_ip_allow_list;
use shared::server::egress::EgressDestinations;
use shared::server::error::ServerError;
use shared::server::tcp::TcpServer;
use shared::server::CID::Parent;
use shared::server::{get_vsock_client, Listener};
use shared::utils::pipe_streams;
use shared::EGRESS_PROXY_PORT;
use shared::EGRESS_PROXY_VSOCK_PORT;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Error)]
pub enum EgressProxyError {
    #[error("Failed to get context in egress proxy - {0}")]
    ContextError(#[from] crate::ContextError),
    #[error("An error occurred while launching the egress proxy - {0}")]
    ServerError(#[from] ServerError),
}

pub struct EgressProxy;

impl EgressProxy {
    pub async fn listen() -> Result<(), EgressProxyError> {
        log::info!("Egress proxy started on port {EGRESS_PROXY_PORT}");
        let allowed_domains = FeatureContext::get()?.egress.allow_list;
        let mut server = TcpServer::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            EGRESS_PROXY_PORT,
        ))
        .await?;

        loop {
            if let Ok(stream) = server.accept().await {
                tokio::spawn(Self::handle_egress_connection(
                    stream,
                    allowed_domains.clone(),
                ));
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn handle_egress_connection(
        mut external_stream: TcpStream,
        allowed_domains: EgressDestinations,
    ) -> Result<(), DNSError> {
        let mut buf = vec![0u8; 4096];
        let n = external_stream.read(&mut buf).await?;
        let customer_data = &mut buf[..n];

        let mut data_plane_stream = get_vsock_client(EGRESS_PROXY_VSOCK_PORT, Parent).await?;

        let fd = external_stream.as_raw_fd();
        let (ip, port) = Self::get_destination(fd)?;
        check_ip_allow_list(ip.to_string(), allowed_domains.clone())?;

        let external_request = ExternalRequest {
            ip,
            data: customer_data.to_vec(),
            port,
        }
        .to_bytes()?;

        data_plane_stream.write_all(&external_request).await?;

        pipe_streams(external_stream, data_plane_stream).await?;
        Ok(())
    }

    #[cfg(not(feature = "enclave"))]
    fn get_destination(_: RawFd) -> Result<(Ipv4Addr, u16), DNSError> {
        // Hardcode egress IP for docker setup as SO_ORIGINAL_DST is not supported
        let addr = std::env::var("TEST_EGRESS_IP")
            .expect("TEST_EGRESS_IP not found in env")
            .parse::<Ipv4Addr>()
            .expect("Invalid IP address");
        Ok((addr, 443))
    }

    #[cfg(feature = "enclave")]
    fn get_destination(fd: RawFd) -> Result<(Ipv4Addr, u16), DNSError> {
        use libc::sockaddr_in;
        use libc::sockaddr_in6;
        use libc::socklen_t;
        use std::io::Error;

        println!("GETTING DESTIONATION!!!");

        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_6: sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;

        let response_code = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut _,
                &mut len as *mut _,
            )
        };

        if response_code == -1 {
            let response_code = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::SO_ORIGINAL_DST,
                    &mut addr as *mut _ as *mut _,
                    &mut len as *mut _,
                )
            };
            let e = Error::last_os_error();
            Err(e.into())
        } else {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            println!("GOT IP!!! {}", ip.to_string());
            let port = u16::from_be(addr.sin_port);
            Ok((ip, port))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::egressproxy::EgressDestinations;
    use shared::server::egress::check_domain_allow_list;
    use shared::server::egress::check_ip_allow_list;
    use shared::server::egress::{
        EgressError::EgressDomainNotAllowed, EgressError::EgressIpNotAllowed,
    };

    #[test]
    fn test_valid_all_domains() {
        let egress_domains = EgressDestinations {
            exact: vec![],
            wildcard: vec![],
            allow_all: true,
            ips: vec![],
        };
        assert_eq!(
            check_domain_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_valid_exact_domain() {
        let egress_domains = EgressDestinations {
            exact: vec!["app.evervault.com".to_string()],
            wildcard: vec![],
            allow_all: false,
            ips: vec![],
        };
        assert_eq!(
            check_domain_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_valid_wildcard_domain() {
        let egress_domains = EgressDestinations {
            exact: vec![],
            wildcard: vec!["evervault.com".to_string()],
            allow_all: false,
            ips: vec![],
        };
        assert_eq!(
            check_domain_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_invalid_domain() {
        let egress_domains = EgressDestinations {
            exact: vec![],
            wildcard: vec!["evervault.com".to_string()],
            allow_all: false,
            ips: vec![],
        };
        let result = check_domain_allow_list("google.com".to_string(), egress_domains);
        assert!(matches!(result, Err(EgressDomainNotAllowed(_))));
    }

    #[test]
    fn test_invalid_ip() {
        let egress_domains = EgressDestinations {
            exact: vec![],
            wildcard: vec![],
            allow_all: false,
            ips: vec!["2.2.2.2".to_string()],
        };
        let result = check_ip_allow_list("1.1.1.1".to_string(), egress_domains);
        assert!(matches!(result, Err(EgressIpNotAllowed(_))));
    }
}
