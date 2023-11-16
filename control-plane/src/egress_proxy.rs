use crate::error::{Result, ServerError};
use shared::rpc::request::ExternalRequest;
use shared::server::egress::{check_allow_list, get_hostname, EgressDomains};
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use shared::utils::pipe_streams;
use shared::{env_var_present_and_true, EGRESS_PROXY_VSOCK_PORT};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use lazy_static::lazy_static;

pub struct EgressProxy;

#[allow(dead_code)] // is used in lazy static
const ALLOW_PRIVATE_EGRESS_OVERRIDE_KEY: &str = "EV_ALLOW_PRIVATE_IP_EGRESS";

lazy_static! {
    static ref ALLOW_EGRESS_TO_INTERNAL_IPS: bool =
        env_var_present_and_true!(ALLOW_PRIVATE_EGRESS_OVERRIDE_KEY);
}

impl EgressProxy {
    pub async fn listen() -> Result<()> {
        let mut server = match get_vsock_server(EGRESS_PROXY_VSOCK_PORT, Parent).await {
            Ok(server) => server,
            Err(e) => {
                log::error!("Error starting egress proxy - {e:?}");
                return Err(e.into());
            }
        };
        log::info!("Egress proxy started");
        let allowed_domains = shared::server::egress::get_egress_allow_list_from_env();

        loop {
            let domains = allowed_domains.clone();
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, domains).await {
                            log::error!(
                                "An error occurred while handling an egress connection - {e:?}"
                            );
                        }
                    });
                }
                Err(e) => {
                    log::error!("An error occurred accepting the egress connection — {e:?}");
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn handle_connection<T: AsyncReadExt + AsyncWriteExt + Unpin>(
        mut external_stream: T,
        egress_domains: EgressDomains,
    ) -> Result<(u64, u64)> {
        log::debug!("Received request to egress proxy");
        let mut request_buffer = [0; 4096];
        let packet_size = external_stream.read(&mut request_buffer).await?;
        let req = &request_buffer[..packet_size];
        let external_request = ExternalRequest::from_bytes(req.to_vec())?;
        let connect_ip: Ipv4Addr =
            match validate_requested_ip(&external_request.ip, *ALLOW_EGRESS_TO_INTERNAL_IPS) {
                Ok(ip) => ip,
                Err(e) => {
                    let _ = external_stream.shutdown().await;
                    return Err(e);
                }
            };

        let hostname = match get_hostname(external_request.data.clone()) {
            Ok(hostname) => hostname,
            Err(_) => external_request.hostname,
        };
        if let Err(err) = check_allow_list(hostname.clone(), egress_domains) {
            let _ = external_stream.shutdown().await;
            log::info!("Blocking request to {hostname} - {err}");
            return Ok((0, 0));
        };

        let mut remote_stream = TcpStream::connect((connect_ip, external_request.port)).await?;
        remote_stream.write_all(&external_request.data).await?;

        let joined_streams = pipe_streams(external_stream, remote_stream).await?;
        Ok(joined_streams)
    }
}

// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
fn is_not_globally_reachable_ip(ip_addr: &Ipv4Addr) -> bool {
    if ip_addr.is_private()
        || ip_addr.is_loopback()
        || ip_addr.is_link_local()
        || ip_addr.is_broadcast()
        || ip_addr.is_documentation()
    {
        return true;
    }
    match ip_addr.octets() {
        [192, 88, 99, ..] => true, // 6to4 Relay Anycast
        [192, 0, 0, final_octet] => final_octet == 170 || final_octet == 171, // NAT64/DNS64 Discovery
        [198, second_octet, ..] => second_octet == 18 || second_octet == 19,  // Benchmarking
        [100, second_octet, ..] => second_octet & 0b1100_0000 == 0b0100_0000, // Shared
        [leading_octet, ..] => leading_octet >= 240 || leading_octet == 0, // Reserved or this host
    }
}

fn validate_requested_ip(ip_addr: &str, allow_egress_to_internal: bool) -> Result<Ipv4Addr> {
    match ip_addr.parse::<Ipv4Addr>() {
        Ok(parsed_addr)
            if is_not_globally_reachable_ip(&parsed_addr) && !allow_egress_to_internal =>
        {
            log::error!("Blocking request to internal IP");
            Err(ServerError::IllegalInternalIp(parsed_addr))
        }
        Err(e) => {
            log::error!("Failed to parse IP");
            Err(ServerError::InvalidIp(e))
        }
        Ok(ip_addr) => Ok(ip_addr),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn attempt_egress_to_private_ip_without_override() {
        let ip_addr = "10.0.0.1";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => {
                assert!(matches!(e, ServerError::IllegalInternalIp(_)))
            }
        }
    }

    #[test]
    fn attempt_egress_to_private_ip_with_override() {
        let ip_addr = "10.0.0.1";
        match validate_requested_ip(ip_addr, true) {
            Ok(parsed_addr) => assert_eq!(ip_addr.parse::<Ipv4Addr>().unwrap(), parsed_addr),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn attempt_egress_to_invalid_ip() {
        let ip_addr = "256.256.256.256";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => assert!(matches!(e, ServerError::InvalidIp(_))),
        }
    }

    #[test]
    fn attempt_egress_to_valid_public_ip() {
        let ip_addr = "76.76.21.21";
        match validate_requested_ip(ip_addr, false) {
            Ok(parsed_addr) => assert_eq!(ip_addr.parse::<Ipv4Addr>().unwrap(), parsed_addr),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn attempt_egress_to_loopback() {
        let ip_addr = "127.0.0.1";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => assert!(matches!(e, ServerError::IllegalInternalIp(_))),
        }
    }

    #[test]
    fn attempt_egress_to_link_local() {
        let ip_addr = "169.254.0.1";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => assert!(matches!(e, ServerError::IllegalInternalIp(_))),
        }
    }

    #[test]
    fn attempt_egress_to_shared_address_space() {
        let ip_addr = "100.64.0.2";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => assert!(matches!(e, ServerError::IllegalInternalIp(_))),
        }
    }

    #[test]
    fn attempt_egress_to_this_host() {
        let ip_addr = "0.0.0.0";
        match validate_requested_ip(ip_addr, false) {
            Ok(_) => panic!(),
            Err(e) => assert!(matches!(e, ServerError::IllegalInternalIp(_))),
        }
    }
}
