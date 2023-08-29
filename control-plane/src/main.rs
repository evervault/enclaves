use control_plane::clients::{cert_provisioner, mtls_config};
use control_plane::dns::{ExternalAsyncDnsResolver, InternalAsyncDnsResolver};
use control_plane::stats_client::StatsClient;
use control_plane::stats_proxy::StatsProxy;
use control_plane::{config_server, tls_proxy};
use shared::server::error::ServerResult;
use shared::storage;
use shared::{print_version, utils::pipe_streams, ENCLAVE_CONNECT_PORT};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, Duration};

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use control_plane::{
    clients::sns::{ControlPlaneSnsClient, DeregistrationMessage},
    configuration::{self, Environment},
    e3proxy, enclave_connection,
    error::Result,
    health,
};

#[cfg(feature = "enclave")]
const CONTROL_PLANE_PORT: u16 = 443;
#[cfg(not(feature = "enclave"))]
const CONTROL_PLANE_PORT: u16 = 3031;

const PROXY_PROTOCOL_MIN_VERSION: semver::Version = semver::Version::new(0, 0, 30);

#[tokio::main]
async fn main() -> Result<()> {
    print_version!("Control Plane");
    println!("Starting control plane on {CONTROL_PLANE_PORT}");
    let e3_proxy = e3proxy::E3Proxy::new();

    let provisioner_proxy = tls_proxy::TlsProxy::new(
        configuration::get_cert_provisoner_host(),
        3000,
        shared::ENCLAVE_CERT_PORT,
        InternalAsyncDnsResolver::new_resolver().expect("Failed to create internal dns resolver"),
    );

    let acme_proxy = tls_proxy::TlsProxy::new(
        configuration::get_acme_host(),
        443,
        shared::ENCLAVE_ACME_PORT,
        ExternalAsyncDnsResolver::new_resolver().expect("Failed to create external dns resolver"),
    );

    StatsClient::init();

    let mtls_config = mtls_config::CertProvisionerMtlsCerts::from_env_vars()
        .expect("Couldn't read in env vars for mtls certs");

    println!("MTLS Certs loaded for Cert Provisioner");

    let cert_provisioner_client = cert_provisioner::CertProvisionerClient::new(
        mtls_config.client_key_pair(),
        mtls_config.root_cert(),
    );

    let acme_s3_client = storage::s3::S3Client::new(configuration::get_acme_s3_bucket()).await;

    let config_server = config_server::ConfigServer::new(cert_provisioner_client, acme_s3_client);

    #[cfg(not(feature = "network_egress"))]
    {
        listen_for_shutdown_signal();
        let mut health_check_server = health::HealthCheckServer::new().await?;

        let (
            tcp_result,
            e3_result,
            health_check_result,
            config_server_result,
            provisioner_proxy_result,
            acme_proxy_result,
            _,
        ) = tokio::join!(
            tcp_server(),
            e3_proxy.listen(),
            health_check_server.start(),
            config_server.listen(),
            provisioner_proxy.listen(),
            acme_proxy.listen(),
            StatsProxy::listen()
        );

        if let Err(err) = tcp_result {
            eprintln!("Error running TCP server on host: {err:?}");
        };

        if let Err(err) = e3_result {
            eprintln!("Error running E3 proxy on host: {err:?}");
        }

        if let Err(err) = health_check_result {
            eprintln!("Error running health check server on host: {err:?}");
        }

        if let Err(err) = config_server_result {
            eprintln!("Error running config server on host: {err:?}");
        }

        if let Err(err) = provisioner_proxy_result {
            eprintln!("Error running provisioner proxy on host: {err:?}");
        }

        if let Err(err) = acme_proxy_result {
            eprintln!("Error running acme proxy on host: {err:?}");
        }
    }

    #[cfg(feature = "network_egress")]
    {
        listen_for_shutdown_signal();
        let mut health_check_server = health::HealthCheckServer::new().await?;
        let parsed_ip = control_plane::dnsproxy::read_dns_server_ip_from_env_var()
            .unwrap_or(control_plane::dnsproxy::CLOUDFLARE_DNS_SERVER);
        let dns_proxy_server = control_plane::dnsproxy::DnsProxy::new(parsed_ip);
        let (
            tcp_result,
            dns_result,
            egress_result,
            e3_result,
            health_check_result,
            config_server_result,
            provisioner_result,
            acme_proxy_result,
            _,
        ) = tokio::join!(
            tcp_server(),
            dns_proxy_server.listen(),
            control_plane::egressproxy::EgressProxy::listen(),
            e3_proxy.listen(),
            health_check_server.start(),
            config_server.listen(),
            provisioner_proxy.listen(),
            acme_proxy.listen(),
            StatsProxy::listen()
        );

        if let Err(tcp_err) = tcp_result {
            eprintln!("An error occurred in the tcp server - {tcp_err:?}");
        }

        if let Err(dns_err) = dns_result {
            eprintln!("An error occurred in the dns server - {dns_err:?}");
        }

        if let Err(egress_err) = egress_result {
            eprintln!("An error occurred in the egress server - {egress_err:?}");
        }

        if let Err(e3_err) = e3_result {
            eprintln!("An error occurred in the e3 server - {e3_err:?}");
        }

        if let Err(err) = health_check_result {
            eprintln!("Error running health check server on host: {err:?}");
        }

        if let Err(err) = config_server_result {
            eprintln!("Error running config server on host: {err:?}");
        }

        if let Err(err) = provisioner_result {
            eprintln!("Error running provisioner proxy on host: {err:?}");
        }

        if let Err(err) = acme_proxy_result {
            eprintln!("Error running acme proxy on host: {err:?}");
        }
    }

    Ok(())
}

async fn tcp_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let tcp_listener = match TcpListener::bind(addr).await {
        Ok(tcp_listener) => tcp_listener,
        Err(e) => {
            eprintln!("Failed to bind to TCP Socket - {e:?}");
            return Err(e.into());
        }
    };

    let parsed_data_plane_version = configuration::get_data_plane_version()
        .ok()
        .and_then(|raw_data_plane_version| semver::Version::parse(&raw_data_plane_version).ok());

    loop {
        let data_plane_version = parsed_data_plane_version.clone();
        if let Ok((mut connection, _client_socket_addr)) = tcp_listener.accept().await {
            StatsClient::record_request();
            tokio::spawn(async move {
                println!("Accepted incoming TCP stream — {_client_socket_addr:?}");
                let enclave_stream =
                    match enclave_connection::get_connection_to_enclave(ENCLAVE_CONNECT_PORT).await
                    {
                        Ok(enclave_stream) => enclave_stream,
                        Err(e) => {
                            eprintln!("An error occurred while connecting to the enclave — {e:?}");
                            connection
                                .shutdown()
                                .await
                                .expect("Failed to close connection to client");
                            return;
                        }
                    };

                if should_remove_proxy_protocol(data_plane_version.as_ref()) {
                    if let Err(e) = strip_proxy_protocol_and_pipe(connection, enclave_stream).await
                    {
                        eprintln!(
                            "An error occurred while piping the connection over vsock - {e:?}"
                        );
                    }
                } else if let Err(e) = pipe_streams(connection, enclave_stream).await {
                    eprintln!("An error occurred while piping the connection over vsock - {e:?}");
                }
            });
        }
    }
}

fn should_remove_proxy_protocol(data_plane_version: Option<&semver::Version>) -> bool {
    match data_plane_version {
        Some(version) => version.cmp(&PROXY_PROTOCOL_MIN_VERSION) == std::cmp::Ordering::Less,
        _ => false,
    }
}

async fn strip_proxy_protocol_and_pipe<
    T1: AsyncRead + AsyncWrite + std::marker::Unpin + std::marker::Sync,
    T2: AsyncRead + AsyncWrite + std::marker::Unpin + std::marker::Sync,
>(
    connection: T1,
    enclave_stream: T2,
) -> ServerResult<(u64, u64)> {
    let parsed_connection =
        shared::server::proxy_protocol::try_parse_proxy_protocol(connection).await?;
    let pipe_result = pipe_streams(parsed_connection, enclave_stream).await?;
    Ok(pipe_result)
}

// Listen for SIGTERM and deregister task before shutting down
fn listen_for_shutdown_signal() {
    println!("Setting up listener for SIGTERM");
    tokio::spawn(async {
        let sns_client =
            ControlPlaneSnsClient::new(configuration::get_deregistration_topic_arn()).await;

        if configuration::get_rust_env() == Environment::Development {
            //Don't start ctrl-c listener is running locally
            return;
        };

        let ec2_instance_id = configuration::get_ec2_instance_id();
        let cage_uuid = configuration::get_cage_uuid();
        let cage_name = configuration::get_cage_name();
        let app_uuid = configuration::get_app_uuid();

        let (tx, mut rx) = mpsc::unbounded_channel();

        let _ = ctrlc::set_handler(move || {
            tx.send(()).unwrap_or_else(|err| {
                println!("Could not broadcast sigterm to channel: {err:?}");
            })
        })
        .map_err(|err| {
            eprintln!("Error setting up Sigterm handler: {err:?}");
            std::io::Error::new(std::io::ErrorKind::Other, err)
        });

        match rx.recv().await {
            Some(_) => {
                println!("Received SIGTERM - sending message to SNS");
                let sns_message = serde_json::to_string(&DeregistrationMessage::new(
                    ec2_instance_id,
                    cage_uuid,
                    cage_name,
                    app_uuid,
                ))
                .expect("Error deserialising SNS message with serde");
                sns_client.publish_message(sns_message).await;

                println!("Received SIGTERM - sending message to SNS");
                // Wait for 55 seconds before terminating enclave - ECS waits 60 seconds to kill the container
                sleep(Duration::from_millis(55000)).await;

                let output = Command::new("sh")
                    .arg("-c")
                    .arg("nitro-cli terminate-enclave --all")
                    .output()
                    .expect("failed to terminate enclave");

                println!(
                    "Terminated enclave: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            None => {
                eprintln!("Signal watcher returned None.");
            }
        };
    });
}

#[cfg(test)]
mod test {
    use crate::PROXY_PROTOCOL_MIN_VERSION;

    use super::{should_remove_proxy_protocol, strip_proxy_protocol_and_pipe};
    use tokio_test::io::Builder;

    fn build_proxy_protocol_header() -> Vec<u8> {
        let header = ppp::v2::Builder::with_addresses(
            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
            ppp::v2::Protocol::Stream,
            (
                "1.2.3.4:80"
                    .parse::<std::net::SocketAddr>()
                    .expect("Infallible - hardcoded"),
                "5.6.7.8:443"
                    .parse::<std::net::SocketAddr>()
                    .expect("Infallible - hardcoded"),
            ),
        );
        header.build().expect("Infallible - hardcoded")
    }

    #[tokio::test]
    async fn test_proxy_protocol_backwards_compatibility() {
        let buf = build_proxy_protocol_header();
        let mut incoming_mock_builder = Builder::new();
        incoming_mock_builder.read(&buf[..]);
        let dummy_data = b"Hello, world".to_vec();
        incoming_mock_builder.read(&dummy_data[..]);
        let mock_incoming_proxied_conn = incoming_mock_builder.build();

        let mut target_mock_builder = Builder::new();
        // configure target stream to only expect the bytes following proxy protocol
        target_mock_builder.write(&dummy_data[..]);
        let mock_target_conn = target_mock_builder.build();
        // test will fail if the target stream receives unexpected data
        let pipe_result =
            strip_proxy_protocol_and_pipe(mock_incoming_proxied_conn, mock_target_conn).await;
        assert!(pipe_result.is_ok());
    }

    #[test]
    fn test_should_remove_proxy_protocol_for_old_data_plane() {
        let old_data_plane = Some(semver::Version::new(0, 0, 20));
        let should_remove_pp = should_remove_proxy_protocol(old_data_plane.as_ref());
        assert!(should_remove_pp);
    }

    #[test]
    fn test_should_not_remove_proxy_protocol_for_new_data_plane() {
        let new_data_plane = Some(semver::Version::new(0, 0, 35));
        let should_remove_pp = should_remove_proxy_protocol(new_data_plane.as_ref());
        assert_eq!(should_remove_pp, false);
    }

    #[test]
    fn test_should_not_remove_proxy_protocol_for_exact_match_data_plane() {
        let min_data_plane = Some(PROXY_PROTOCOL_MIN_VERSION.clone());
        let should_remove_pp = should_remove_proxy_protocol(min_data_plane.as_ref());
        assert_eq!(should_remove_pp, false);
    }
}
