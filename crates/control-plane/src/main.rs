use control_plane::clients::{cert_provisioner, mtls_config};
use control_plane::configuration::get_external_metrics_enabled;
use control_plane::dns::{ExternalAsyncDnsResolver, InternalAsyncDnsResolver};
use control_plane::health::HealthCheckServer;
use control_plane::orchestration::Orchestration;
use control_plane::stats::{client::StatsClient, get_stats_target_ip, proxy::StatsProxy};
use control_plane::stats::{EXTERNAL_METRIC_PORT, INTERNAL_METRIC_PORT};
use control_plane::{config_server, tls_proxy};
use shared::notify_shutdown::{NotifyShutdown, Service};
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    print_version,
    utils::pipe_streams,
    ENCLAVE_CONNECT_PORT,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use storage_client_interface::s3;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::channel;

use control_plane::{
    configuration::{self, Environment},
    e3proxy,
    error::Result,
    health,
};

#[cfg(feature = "enclave")]
const CONTROL_PLANE_PORT: u16 = 443;
#[cfg(not(feature = "enclave"))]
const CONTROL_PLANE_PORT: u16 = 3031;

#[tokio::main]
async fn main() -> Result<()> {
    shared::logging::init_env_logger();
    print_version!("Control Plane");
    log::debug!("Starting control plane on {CONTROL_PLANE_PORT}");
    let e3_proxy = e3proxy::E3Proxy::new();

    let provisioner_proxy = tls_proxy::TlsProxy::new(
        vec![configuration::get_cert_provisoner_host()],
        3000,
        shared::ENCLAVE_CERT_PORT,
        InternalAsyncDnsResolver::new_resolver(),
    );

    let acme_proxy = tls_proxy::TlsProxy::new(
        configuration::get_acme_hosts(),
        443,
        shared::ENCLAVE_ACME_PORT,
        ExternalAsyncDnsResolver::new_resolver(),
    );

    StatsClient::init();

    let mtls_config = mtls_config::CertProvisionerMtlsCerts::from_env_vars()
        .expect("Couldn't read in env vars for mtls certs");

    log::info!("MTLS Certs loaded for Cert Provisioner");

    let cert_provisioner_client = cert_provisioner::CertProvisionerClient::new(
        mtls_config.client_key_pair(),
        mtls_config.root_cert(),
    );

    let acme_s3_client = s3::StorageClient::new(configuration::get_acme_s3_bucket()).await;

    let config_server = config_server::ConfigServer::new(cert_provisioner_client, acme_s3_client);

    let (shutdown_sender, shutdown_receiver) = channel(1);

    let mut health_check_server = HealthCheckServer::new(shutdown_receiver);

    listen_for_shutdown_signal();
    schedule_statsd_proxies();

    tokio::spawn(
        e3_proxy
            .listen()
            .notify_shutdown(Service::E3Proxy, shutdown_sender.clone()),
    );

    tokio::spawn(async move {
        if let Err(e) = health_check_server.start().await {
            log::error!("Error starting health check server - {e:?}");
        }
    });

    tokio::spawn(
        provisioner_proxy
            .listen()
            .notify_shutdown(Service::ProvisionerProxy, shutdown_sender.clone()),
    );

    tokio::spawn(
        acme_proxy
            .listen()
            .notify_shutdown(Service::AcmeProxy, shutdown_sender.clone()),
    );

    tokio::spawn({
        let shutdown_sender = shutdown_sender.clone();
        async move {
            if let Err(e) = config_server
                .listen()
                .notify_shutdown(Service::ConfigServer, shutdown_sender)
                .await
            {
                log::error!("Error starting config server - {e:?}");
            }
        }
    });

    #[cfg(feature = "network_egress")]
    {
        let parsed_ip = control_plane::dnsproxy::read_dns_server_ips_from_env_var()
            .unwrap_or_else(|| control_plane::dnsproxy::DNS_SERVERS.clone());

        let dns_proxy_server = control_plane::dnsproxy::DnsProxy::new(parsed_ip);

        tokio::spawn(
            dns_proxy_server
                .listen()
                .notify_shutdown(Service::DnsProxy, shutdown_sender.clone()),
        );
        tokio::spawn(
            control_plane::egressproxy::EgressProxy::listen()
                .notify_shutdown(Service::EgressProxy, shutdown_sender.clone()),
        );
    }

    tokio::spawn(Orchestration::start_enclave());

    tcp_server().await
}

fn schedule_statsd_proxies() {
    let external_metrics_enabled = get_external_metrics_enabled();
    let internal_stats_target_addr = SocketAddr::new(get_stats_target_ip(), INTERNAL_METRIC_PORT);
    let external_stats_target_addr = SocketAddr::new(get_stats_target_ip(), EXTERNAL_METRIC_PORT);

    tokio::spawn(async move {
        let mut targets = vec![internal_stats_target_addr];
        if external_metrics_enabled {
            targets.push(external_stats_target_addr);
        }
        StatsProxy::spawn(shared::INTERNAL_STATS_BRIDGE_PORT, targets).await
    });

    if external_metrics_enabled {
        tokio::spawn(async move {
            StatsProxy::spawn(
                shared::EXTERNAL_STATS_BRIDGE_PORT,
                vec![external_stats_target_addr],
            )
            .await
        });
    }
}

async fn tcp_server() -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), CONTROL_PLANE_PORT);

    let tcp_listener = match TcpListener::bind(addr).await {
        Ok(tcp_listener) => tcp_listener,
        Err(e) => {
            log::error!("Failed to bind to TCP Socket - {e:?}");
            return Err(e.into());
        }
    };

    loop {
        let (mut connection, client_socket_addr) = match tcp_listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("Failed to accept incoming TCP stream - {e:?}");
                continue;
            }
        };
        StatsClient::record_request();
        tokio::spawn(async move {
            log::debug!("Accepted incoming TCP stream — {client_socket_addr:?}");
            let enclave_stream =
                match Bridge::get_client_connection(ENCLAVE_CONNECT_PORT, Direction::HostToEnclave)
                    .await
                {
                    Ok(enclave_stream) => enclave_stream,
                    Err(e) => {
                        log::error!("An error occurred while connecting to the enclave — {e:?}");
                        connection
                            .shutdown()
                            .await
                            .expect("Failed to close connection to client");
                        return;
                    }
                };

            if let Err(e) = pipe_streams(connection, enclave_stream).await {
                log::error!("An error occurred while piping the connection over vsock - {e:?}");
            }
        });
    }
}

// Listen for SIGTERM and deregister task before shutting down
fn listen_for_shutdown_signal() {
    log::debug!("Setting up listener for SIGTERM");
    tokio::spawn(async {
        if configuration::get_rust_env() == Environment::Development {
            //Don't start ctrl-c listener is running locally
            return;
        };

        let (tx, mut rx) = mpsc::unbounded_channel();

        let _ = ctrlc::set_handler(move || {
            tx.send(()).unwrap_or_else(|err| {
                log::warn!("Could not broadcast sigterm to channel: {err:?}");
            })
        })
        .map_err(|err| {
            log::error!("Error setting up Sigterm handler: {err:?}");
            std::io::Error::other(err)
        });

        match rx.recv().await {
            Some(_) => {
                log::info!("SIGTERM received. Setting Enclave draining flag to true and waiting 55 seconds to terminate Enclave.");
                if let Err(err) = health::IS_DRAINING.set(true) {
                    log::error!(
                        "Error setting IS_DRAINING to true: {err:?}, continuing to shutdown"
                    );
                }

                // Wait for 55 seconds before terminating enclave - ECS waits 55 seconds to kill the container
                sleep(Duration::from_millis(55000)).await;

                match Orchestration::shutdown_all_enclaves().await {
                    Ok(output) => log::info!("Terminated enclave successfully: {output}"),
                    Err(err) => log::error!("Error terminating enclave: {err:?}"),
                }
            }
            None => {
                log::error!("Signal watcher returned None.");
            }
        };
    });
}
