use shared::utils::pipe_streams;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(not(feature = "enclave"))]
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::{io::AsyncWriteExt, net::TcpListener};

use crate::error::Result;
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

mod e3proxy;
mod error;
use control_plane::{
    clients::sns::{ControlPlaneSnsClient, DeregistrationMessage},
    configuration::{self, Environment},
};

#[cfg(feature = "enclave")]
const CONTROL_PLANE_PORT: u16 = 443;
#[cfg(not(feature = "enclave"))]
const CONTROL_PLANE_PORT: u16 = 3031;

use shared::print_version;
#[cfg(feature = "enclave")]
use shared::ENCLAVE_CID;
use shared::ENCLAVE_CONNECT_PORT;

#[tokio::main]
async fn main() -> Result<()> {
    print_version!("Control Plane");
    println!("Starting control plane on {}", CONTROL_PLANE_PORT);
    let e3_proxy = e3proxy::E3Proxy::new();
    #[cfg(not(feature = "network_egress"))]
    {
        listen_for_shutdown_signal();
        let (tcp_result, e3_result) = tokio::join!(tcp_server(), e3_proxy.listen());
        if let Err(err) = tcp_result {
            eprintln!("Error running TCP server on host: {:?}", err);
        };

        if let Err(err) = e3_result {
            eprintln!("Error running E3 proxy on host: {:?}", err);
        }
    }

    #[cfg(feature = "network_egress")]
    {
        listen_for_shutdown_signal();
        let (tcp_result, dns_result, egress_result, e3_result) = tokio::join!(
            tcp_server(),
            control_plane::dnsproxy::DnsProxy::listen(),
            control_plane::egressproxy::EgressProxy::listen(),
            e3_proxy.listen()
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
    }

    Ok(())
}

#[cfg(not(feature = "enclave"))]
async fn get_connection_to_enclave() -> std::io::Result<TcpStream> {
    let ip_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    println!(
        "Connecting to tcp data plane on ({},{})",
        ip_addr, ENCLAVE_CONNECT_PORT
    );
    TcpStream::connect(std::net::SocketAddr::new(ip_addr, ENCLAVE_CONNECT_PORT)).await
}

#[cfg(feature = "enclave")]
async fn get_connection_to_enclave() -> std::io::Result<VsockStream> {
    println!(
        "Connecting to enclave on ({},{})",
        ENCLAVE_CID, ENCLAVE_CONNECT_PORT
    );
    VsockStream::connect(ENCLAVE_CID, ENCLAVE_CONNECT_PORT.into()).await
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
                let enclave_stream = match get_connection_to_enclave().await {
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
