use crate::error::{Result, ServerError};
use shared::rpc::request::ExternalRequest;
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
        println!("Egress proxy started");
        let mut server = get_vsock_server(EGRESS_PROXY_VSOCK_PORT).await?;

        loop {
            match server.accept().await {
                Ok(stream) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream).await {
                            eprintln!(
                                "An error occurred while handling an egress connection - {e:?}"
                            );
                        }
                    });
                }
                Err(e) => {
                    eprintln!("An error occurred accepting the egress connection — {e:?}");
                }
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn handle_connection<T: AsyncReadExt + AsyncWriteExt + Unpin>(
        mut external_stream: T,
    ) -> Result<(u64, u64)> {
        println!("Received request to egress proxy");
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

        let mut remote_stream = TcpStream::connect((connect_ip, external_request.port)).await?;
        remote_stream.write_all(&external_request.data).await?;

        let joined_streams = pipe_streams(external_stream, remote_stream).await?;
        Ok(joined_streams)
    }
}

fn validate_requested_ip(ip_addr: &str, allow_egress_to_internal: bool) -> Result<Ipv4Addr> {
    match ip_addr.parse::<Ipv4Addr>() {
        Ok(parsed_addr) if parsed_addr.is_private() && !allow_egress_to_internal => {
            println!("Blocking request to internal IP");
            Err(ServerError::IllegalInternalIp(parsed_addr))
        }
        Err(e) => {
            println!("Failed to parse IP");
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
}
