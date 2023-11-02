use super::error::DNSError;
use crate::dns::error::DNSError::MissingIP;
use crate::FeatureContext;
use cached::Cached;
use shared::rpc::request::ExternalRequest;
use shared::server::egress::{EgressDomains, check_allow_list, get_hostname};
use shared::server::error::ServerError;
use shared::server::tcp::TcpServer;
use shared::server::CID::Parent;
use shared::server::{get_vsock_client, Listener};
use shared::utils::pipe_streams;
use shared::EGRESS_PROXY_VSOCK_PORT;
use thiserror::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rand::seq::SliceRandom;

#[derive(Debug, Error)]
pub enum EgressProxyError {
  #[error("Failed to get context in egress proxy - {0}")]
  ContextError(#[from] crate::ContextError),
  #[error("An error occurred while launching the egress proxy - {0}")]
  ServerError(#[from] ServerError)
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
                    port,
                    allowed_domains.clone(),
                ));
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn handle_egress_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut external_stream: T,
        port: u16,
        allowed_domains: EgressDomains,
    ) -> Result<(), DNSError> {
        let mut buf = vec![0u8; 4096];
        let n = external_stream.read(&mut buf).await?;
        let customer_data = &mut buf[..n];

        let hostname = get_hostname(customer_data.to_vec())?;
        check_allow_list(hostname.clone(), allowed_domains.clone())?;

        let fqdn = format!("{hostname}.");
        let cached_ips = crate::cache::HOST_TO_IP
            .lock()
            .await
            .cache_get(&fqdn)
            .map(|cache_entry| cache_entry.ips().to_vec());

        match cached_ips
            .as_ref()
            .and_then(|ips| ips.choose(&mut rand::thread_rng()))
        {
            Some(remote_ip) => {
                let mut data_plane_stream =
                    get_vsock_client(EGRESS_PROXY_VSOCK_PORT, Parent).await?;

                let external_request = ExternalRequest {
                    ip: remote_ip.to_string(),
                    data: customer_data.to_vec(),
                    port,
                }
                .to_bytes()?;

                data_plane_stream.write_all(&external_request).await?;

                pipe_streams(external_stream, data_plane_stream).await?;
                Ok(())
            }
            None => Err(MissingIP(format!("Couldn't find cached ip for {hostname}"))),
        }
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
