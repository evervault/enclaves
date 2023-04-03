use super::error::DNSError;
use crate::dns::cache::Cache;
use crate::dns::error::DNSError::MissingIP;
use shared::rpc::request::ExternalRequest;
use shared::server::error::ServerResult;
use shared::server::tcp::TcpServer;
use shared::server::CID::Parent;
use shared::server::{get_vsock_client, Listener};
use shared::utils::pipe_streams;
use shared::EGRESS_PROXY_VSOCK_PORT;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tls_parser::nom::Finish;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rand::seq::SliceRandom;

pub struct EgressProxy;

impl EgressProxy {
    pub async fn listen(port: u16, allowed_domains: Vec<String>) -> ServerResult<()> {
        println!("Egress proxy started on port {port}");

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

    fn get_hostname(data: Vec<u8>) -> Result<Option<String>, DNSError> {
        let (_, parsed_request) = parse_tls_plaintext(&data)
            .finish()
            .map_err(|tls_parse_err| DNSError::TlsParseError(format!("{tls_parse_err:?}")))?;

        let client_hello = match &parsed_request.msg[0] {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => client_hello,
            _ => return Ok(None),
        };

        let raw_extensions = match client_hello.ext {
            Some(raw_extensions) => raw_extensions,
            _ => return Ok(None),
        };
        let mut destination = "".to_string();
        let (_, extensions) = parse_tls_extensions(raw_extensions)
            .finish()
            .map_err(|tls_parse_err| DNSError::TlsParseError(format!("{tls_parse_err:?}")))?;

        for extension in extensions {
            if let TlsExtension::SNI(sni_vec) = extension {
                for (_, item) in sni_vec {
                    if let Ok(hostname) = std::str::from_utf8(item) {
                        destination = hostname.to_string();
                    }
                }
            }
        }
        Ok(Some(destination))
    }

    fn check_allow_list(hostname: String, allowed_domains: Vec<String>) -> Result<(), DNSError> {
        if allowed_domains.contains(&hostname) {
            Ok(())
        } else {
            Err(DNSError::EgressDomainNotAllowed(hostname))
        }
    }

    async fn handle_egress_connection<T: AsyncRead + AsyncWrite + Unpin>(
        mut external_stream: T,
        port: u16,
        allowed_domains: Vec<String>,
    ) -> Result<(), DNSError> {
        let mut buf = vec![0u8; 4096];

        let n = external_stream.read(&mut buf).await?;
        let customer_data = &mut buf[..n];

        let hostname = match Self::get_hostname(customer_data.to_vec())? {
            Some(hostname) => hostname,
            None => return Err(DNSError::NoHostnameFound),
        };

        Self::check_allow_list(hostname.clone(), allowed_domains.clone())?;

        let cached_ips = Cache::get_ip(hostname.as_ref());

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
