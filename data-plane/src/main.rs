#[cfg(feature = "network_egress")]
use data_plane::dns::{egressproxy::EgressProxy, enclavedns::EnclaveDnsProxy};
use data_plane::{
    crypto::api::CryptoApi,
    env::{init_environment_loader, EnvironmentLoader},
    health::build_health_check_server,
    stats::client::StatsClient,
    stats::proxy::StatsProxy,
    time::ClockSync,
    FeatureContext,
};
#[cfg(not(feature = "tls_termination"))]
use shared::server::Listener;
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    notify_shutdown::{NotifyShutdown, Service},
    print_version,
    server::proxy_protocol::ProxyProtocolServer,
    ENCLAVE_CONNECT_PORT,
};
use tokio::sync::mpsc::Sender;
use tokio::time::Duration;

#[cfg(feature = "enclave")]
fn try_update_fd_limit(soft_limit: u64, hard_limit: u64) {
    if let Err(e) = rlimit::setrlimit(rlimit::Resource::NOFILE, soft_limit, hard_limit) {
        eprintln!("Failed to set enclave file descriptor limit on startup - {e:?}");
    }
    if let Ok((soft_limit, hard_limit)) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
        println!("RLIMIT_NOFILE: SoftLimit={soft_limit}, HardLimit={hard_limit}");
    }
}

const ENCLAVE_CLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(300);

fn main() {
    shared::logging::init_env_logger();
    print_version!("Data Plane");

    #[cfg(feature = "enclave")]
    try_update_fd_limit(rlimit::INFINITY, rlimit::INFINITY);

    let mut args = std::env::args();
    let _ = args.next(); // ignore path to executable
    let data_plane_port = args
        .next()
        .and_then(|port_str| port_str.as_str().parse::<u16>().ok())
        .unwrap_or(8008);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime in data plane");

    let ctx = match FeatureContext::set() {
        Ok(_) => FeatureContext::get()
            .expect("Infallible - feature context read after context is set successfully"),
        Err(e) => {
            log::error!("Failed to set context in enclave, cannot proceed - {e:?}");
            return;
        }
    };

    runtime.block_on(async move {
        let Ok((health_check_server, shutdown_notifier)) = build_health_check_server(
            ctx.healthcheck_port.unwrap_or(data_plane_port),
            ctx.healthcheck,
            ctx.healthcheck_use_tls.unwrap_or(false),
        )
        .await
        else {
            log::error!("Failed to launch in-Enclave healthcheck service, exiting early.");
            return;
        };

        tokio::select! {
          _ = start(data_plane_port, shutdown_notifier) => {},
          _ = health_check_server.run() => {}
        };
    });
}

async fn start(data_plane_port: u16, shutdown_notifier: Sender<Service>) {
    if let Err(e) = StatsClient::init().await {
        log::error!("Failed to register in-Enclave stats client - {e}");
    }
    let context = match FeatureContext::get() {
        Ok(context) => context,
        Err(e) => {
            log::error!("Failed to access context in enclave - {e}");
            return;
        }
    };

    if cfg!(not(feature = "network_egress")) {
        log::info!("Running data plane with egress disabled");
    } else {
        log::info!("Running data plane with egress enabled");
    }

    let env_loader = init_environment_loader();
    let env_loader = match env_loader.load_env_vars().await {
        Ok(env_loader) => env_loader,
        Err(e) => {
            log::error!("An error occurred initializing the enclave environment - {e:?}");
            return;
        }
    };

    // Schedule non-critical stats proxy
    tokio::spawn(async move {
        if let Err(e) = StatsProxy::listen().await {
            log::error!("In-Enclave Stats proxy exited with an error - {e}");
        }
    });

    // Schedule critical services with notify shutdown futures to ensure healthchecks detect any single critical failure.
    tokio::spawn(
        CryptoApi::listen().notify_shutdown(Service::CryptoApi, shutdown_notifier.clone()),
    );
    tokio::spawn(
        ClockSync::run(ENCLAVE_CLOCK_SYNC_INTERVAL)
            .notify_shutdown(Service::ClockSync, shutdown_notifier.clone()),
    );

    #[cfg(feature = "network_egress")]
    {
        tokio::spawn(
            EnclaveDnsProxy::bind_server(context.egress.allow_list.clone())
                .notify_shutdown(Service::DnsProxy, shutdown_notifier.clone()),
        );
        tokio::spawn(
            EgressProxy::listen().notify_shutdown(Service::EgressProxy, shutdown_notifier.clone()),
        );
    }

    start_data_plane(data_plane_port, context, env_loader)
        .notify_shutdown(Service::DataPlane, shutdown_notifier.clone())
        .await;
}

#[cfg(feature = "tls_termination")]
use data_plane::env::NeedCert;
#[cfg(feature = "tls_termination")]
async fn start_data_plane(
    data_plane_port: u16,
    context: FeatureContext,
    env_loader: EnvironmentLoader<NeedCert>,
) {
    log::info!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match Bridge::get_listener(ENCLAVE_CONNECT_PORT, Direction::EnclaveToHost).await {
        Ok(server) => ProxyProtocolServer::from(server),
        Err(error) => return log::error!("Error creating server: {error}"),
    };
    log::debug!("Data plane TCP server created");

    log::info!("TLS Termination enabled in dataplane. Running tls server.");
    if let Err(e) =
        data_plane::server::server::run(server, data_plane_port, context, env_loader).await
    {
        log::error!("Failed to run data plane - {e}");
    }
}

#[cfg(not(feature = "tls_termination"))]
use data_plane::env::Finalize;
#[cfg(not(feature = "tls_termination"))]
use shared::{server::proxy_protocol::ProxiedConnection, utils::pipe_streams};
#[cfg(not(feature = "tls_termination"))]
use tokio::io::AsyncWriteExt;
#[cfg(not(feature = "tls_termination"))]
async fn start_data_plane(
    data_plane_port: u16,
    context: FeatureContext,
    env_loader: EnvironmentLoader<Finalize>,
) {
    log::info!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let mut server =
        match Bridge::get_listener(ENCLAVE_CONNECT_PORT, Direction::EnclaveToHost).await {
            Ok(server) => ProxyProtocolServer::from(server),
            Err(error) => return log::error!("Error creating server: {error}"),
        };
    log::debug!("Data plane TCP server created");
    if let Err(e) = env_loader.finalize_env() {
        log::error!("Errored while finalizing environment - {e:?}");
        return;
    }

    log::info!("Piping TCP streams directly to user process");

    loop {
        let incoming_conn = match server.accept().await {
            Ok(incoming_conn) => incoming_conn,
            Err(e) => {
                log::error!(
                    "An error occurred while accepting the incoming connection — {}",
                    e
                );
                continue;
            }
        };

        tokio::spawn(async move {
            let mut customer_stream =
                match tokio::net::TcpStream::connect(("0.0.0.0", data_plane_port)).await {
                    Ok(customer_stream) => customer_stream,
                    Err(e) => {
                        log::error!(
                            "An error occurred while connecting to the customer process — {}",
                            e
                        );
                        return;
                    }
                };

            if incoming_conn.has_proxy_protocol() && context.forward_proxy_protocol {
                // flush proxy protocol bytes to customer process
                let proxy_protocol = incoming_conn.proxy_protocol().unwrap();
                if let Err(e) = customer_stream.write_all(proxy_protocol.as_bytes()).await {
                    log::error!(
                      "An error occurred while forwarding the proxy protocol to the customer process — {}",
                      e
                  );
                    return;
                }
            }

            if let Err(e) = pipe_streams(incoming_conn, customer_stream).await {
                log::error!("An error occurred piping between the incoming connection and the customer process — {}", e);
                return;
            }
        });
    }
}
