use super::error::DNSError;
use crate::dns::cache::Cache;
use crate::dns::error::DNSError::MissingIP;
use crate::FeatureContext;
use libc::sockaddr_in;
use libc::socklen_t;
use shared::rpc::request::ExternalRequest;
use shared::server::egress::check_allow_list;
use shared::server::egress::get_hostname;
use shared::server::egress::EgressDomains;
use shared::server::error::ServerError;
use shared::server::tcp::TcpServer;
use shared::server::CID::Parent;
use shared::server::{get_vsock_client, Listener};
use shared::utils::pipe_streams;
use shared::EGRESS_PROXY_VSOCK_PORT;
use std::io;
use std::mem;
use std::net::SocketAddrV4;
use std::net::TcpStream;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rand::seq::SliceRandom;

#[derive(Debug, Error)]
pub enum EgressProxyError {
    #[error("Failed to get context in egress proxy - {0}")]
    ContextError(#[from] crate::ContextError),
    #[error("An error occurred while launching the egress proxy - {0}")]
    ServerError(#[from] ServerError),
}

pub struct EgressProxy;

impl EgressProxy {
    pub async fn listen(port: u16) -> Result<(), EgressProxyError> {
        log::info!("Egress proxy started on port {port}");
        let allowed_domains = FeatureContext::get()?.egress.allow_list;
        let mut server =
            TcpServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)).await?;

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

    fn get_original_dst(fd: RawFd) -> Result<(Ipv4Addr, u16), ()> {
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;


        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut _,
                &mut len as *mut _,
            )
        };

        if ret == -1 {
            let e = io::Error::last_os_error();
            println!("ERRR {:?}", e);
            Err(())
            //Err(io::Error::last_os_error())
        } else {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            println!("IP: {:?}, PORT: {:?}", ip, port);
            // Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            Ok((ip, port))
        }
    }

    async fn handle_egress_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut external_stream: T,
        allowed_domains: EgressDomains,
    ) -> Result<(), DNSError> {
        let mut buf = vec![0u8; 4096];
        let n = external_stream.read(&mut buf).await?;
        let customer_data = &mut buf[..n];
        println!("Customer data: {:?}", customer_data.len());
        println!("Recieved request to egress proxy");
        let fd = external_stream.as_raw_fd();
        println!("File descriptor: {:?}", fd);
        let (add, port) = Self::get_original_dst(fd).unwrap();
        // let hostname = get_hostname(customer_data.to_vec())?;
        // check_allow_list(hostname.clone(), allowed_domains.clone())?;

        // let cached_ips = Cache::get_ip(hostname.as_ref());

        let mut data_plane_stream = get_vsock_client(EGRESS_PROXY_VSOCK_PORT, Parent).await?;

        println!("Sending to ip: {} {}", add.to_string(), port);
        let external_request = ExternalRequest {
            ip: add.to_string(),
            data: customer_data.to_vec(),
            port: 443,
        }
        .to_bytes()?;

        println!("Sending to control plane");
        data_plane_stream.write_all(&external_request).await?;

        pipe_streams(external_stream, data_plane_stream).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::egressproxy::EgressDomains;
    use shared::server::egress::{check_allow_list, EgressError::EgressDomainNotAllowed};

    #[test]
    fn test_valid_all_domains() {
        let egress_domains = EgressDomains {
            exact: vec![],
            wildcard: vec![],
            allow_all: true,
        };
        assert_eq!(
            check_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_valid_exact_domain() {
        let egress_domains = EgressDomains {
            exact: vec!["app.evervault.com".to_string()],
            wildcard: vec![],
            allow_all: false,
        };
        assert_eq!(
            check_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_valid_wildcard_domain() {
        let egress_domains = EgressDomains {
            exact: vec![],
            wildcard: vec!["evervault.com".to_string()],
            allow_all: false,
        };
        assert_eq!(
            check_allow_list("app.evervault.com".to_string(), egress_domains).unwrap(),
            ()
        );
    }
    #[test]
    fn test_invalid_domain() {
        let egress_domains = EgressDomains {
            exact: vec![],
            wildcard: vec!["evervault.com".to_string()],
            allow_all: false,
        };
        let result = check_allow_list("google.com".to_string(), egress_domains);
        assert!(matches!(result, Err(EgressDomainNotAllowed(_))));
    }
}
