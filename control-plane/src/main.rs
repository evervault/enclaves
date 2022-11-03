use control_plane::clients::{cert_provisioner, mtls_config};
use control_plane::{cert_proxy, config_server};
use shared::{print_version, utils::pipe_streams, ENCLAVE_CONNECT_PORT};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::sync::mpsc;
use tokio::{io::AsyncWriteExt, net::TcpListener};

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

#[tokio::main]
async fn main() -> Result<()> {
    print_version!("Control Plane");
    println!("Starting control plane on {}", CONTROL_PLANE_PORT);
    let e3_proxy = e3proxy::E3Proxy::new();
    let cert_proxy = cert_proxy::CertProxy::new();

    let mtls_config = mtls_config::CertProvisionerMtlsCerts::from_env_vars()
        .expect("Couldn't read in env vars for mtls certs");

    println!("MTLS Certs loaded for Cert Provisioner");

    let cert_provisioner_client = cert_provisioner::CertProvisionerClient::new(
        mtls_config.client_key_pair(),
        mtls_config.root_cert(),
    );
    let config_server = config_server::ConfigServer::new(cert_provisioner_client);

    #[cfg(not(feature = "network_egress"))]
    {
        listen_for_shutdown_signal();
        let mut health_check_server = health::HealthCheckServer::new().await?;

        let (tcp_result, e3_result, health_check_result, config_server_result, cert_proxy_result) = tokio::join!(
            tcp_server(),
            e3_proxy.listen(),
            health_check_server.start(),
            config_server.listen(),
            cert_proxy.listen()
        );

        if let Err(err) = tcp_result {
            eprintln!("Error running TCP server on host: {:?}", err);
        };

        if let Err(err) = e3_result {
            eprintln!("Error running E3 proxy on host: {:?}", err);
        }

        if let Err(err) = health_check_result {
            eprintln!("Error running health check server on host: {:?}", err);
        }

        if let Err(err) = config_server_result {
            eprintln!("Error running config server on host: {:?}", err);
        }

        if let Err(err) = cert_proxy_result {
            eprintln!("Error running cert proxy on host: {:?}", err);
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
            cert_proxy_result,
        ) = tokio::join!(
            tcp_server(),
            dns_proxy_server.listen(),
            control_plane::egressproxy::EgressProxy::listen(),
            e3_proxy.listen(),
            health_check_server.start(),
            config_server.listen(),
            cert_proxy.listen()
        );

        if let Err(tcp_err) = tcp_result {
            eprintln!("An error occurred in the tcp server - {:?}", tcp_err);
        }

        if let Err(dns_err) = dns_result {
            eprintln!("An error occurred in the dns server - {:?}", dns_err);
        }

        if let Err(egress_err) = egress_result {
            eprintln!("An error occurred in the egress server - {:?}", egress_err);
        }

        if let Err(e3_err) = e3_result {
            eprintln!("An error occurred in the e3 server - {:?}", e3_err);
        }

        if let Err(err) = health_check_result {
            eprintln!("Error running health check server on host: {:?}", err);
        }

        if let Err(err) = config_server_result {
            eprintln!("Error running config server on host: {:?}", err);
        }

        if let Err(err) = cert_proxy_result {
            eprintln!("Error running cert proxy on host: {:?}", err);
        }
    }

    Ok(())
}

async fn tcp_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let tcp_listener = match TcpListener::bind(addr).await {
        Ok(tcp_listener) => tcp_listener,
        Err(e) => {
            eprintln!("Failed to bind to TCP Socket - {:?}", e);
            return Err(e.into());
        }
    };

    loop {
        if let Ok((mut connection, _client_socket_addr)) = tcp_listener.accept().await {
            tokio::spawn(async move {
                println!("Accepted incoming TCP stream — {:?}", _client_socket_addr);
                let enclave_stream =
                    match enclave_connection::get_connection_to_enclave(ENCLAVE_CONNECT_PORT).await
                    {
                        Ok(enclave_stream) => enclave_stream,
                        Err(e) => {
                            eprintln!(
                                "An error occurred while connecting to the enclave — {:?}",
                                e
                            );
                            connection
                                .shutdown()
                                .await
                                .expect("Failed to close connection to client");
                            return;
                        }
                    };

                if let Err(e) = pipe_streams(connection, enclave_stream).await {
                    eprintln!(
                        "An error occurred while piping the connection over vsock - {:?}",
                        e
                    );
                }
            });
        }
    }
}

// Listen for SIGTERM and deregister task before shutting down
fn listen_for_shutdown_signal() {
    println!("Setting up listener for SIGTERM");
    tokio::spawn(async {
        let sns_client = ControlPlaneSnsClient::new(configuration::get_deregistration_topic_arn());

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
                println!("Could not broadcast sigterm to channel: {:?}", err);
            })
        })
        .map_err(|err| {
            eprintln!("Error setting up Sigterm handler: {:?}", err);
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
            }
            None => {
                eprintln!("Signal watcher returned None.");
            }
        };
    });
}
