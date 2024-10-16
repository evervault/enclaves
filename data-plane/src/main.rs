#[cfg(not(feature = "tls_termination"))]
use shared::server::Listener;
use shared::server::CID::Enclave;
use shared::{print_version, server::get_vsock_server_with_proxy_protocol};

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDnsProxy;
#[cfg(not(feature = "tls_termination"))]
use data_plane::env::Environment;
use data_plane::health::start_health_check_server;
use data_plane::stats_client::StatsClient;
use data_plane::time::ClockSync;
use data_plane::FeatureContext;
use shared::ENCLAVE_CONNECT_PORT;
use tokio::time::Duration;

#[cfg(feature = "enclave")]
fn try_update_fd_limit(soft_limit: u64, hard_limit: u64) {
    if let Err(e) = rlimit::setrlimit(rlimit::Resource::NOFILE, soft_limit, hard_limit) {
        eprintln!("Failed to set enclave file descriptor limit on startup - {e:?}");
    }
    if let Ok((soft_limit, hard_limit)) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
        println!(
            "RLIMIT_NOFILE: SoftLimit={}, HardLimit={}",
            soft_limit, hard_limit
        );
    }
}

#[cfg(feature = "enclave")]
const ENCLAVE_NOFILE_SOFT_LIMIT: u64 = 4096;
#[cfg(feature = "enclave")]
const ENCLAVE_NOFILE_HARD_LIMIT: u64 = 16384;
const ENCLAVE_CLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(300);

fn main() {
    shared::logging::init_env_logger();
    print_version!("Data Plane");

    #[cfg(feature = "enclave")]
    try_update_fd_limit(ENCLAVE_NOFILE_SOFT_LIMIT, ENCLAVE_NOFILE_HARD_LIMIT);

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
        tokio::join!(
            start(data_plane_port),
            start_health_check_server(
                ctx.healthcheck_port.unwrap_or(data_plane_port),
                ctx.healthcheck,
                ctx.healthcheck_use_tls.unwrap_or(false)
            )
        );
    });
}

#[cfg(not(feature = "network_egress"))]
async fn start(data_plane_port: u16) {
    use data_plane::{crypto::api::CryptoApi, stats::StatsProxy};

    StatsClient::init();

    let context = match FeatureContext::get() {
        Ok(context) => context,
        Err(e) => {
            log::error!("Failed to access context in enclave - {e}");
            return;
        }
    };

    log::info!("Running data plane with egress disabled");
    let (_, e3_api_result, stats_result, _) = tokio::join!(
        start_data_plane(data_plane_port, context),
        CryptoApi::listen(),
        StatsProxy::listen(),
        ClockSync::run(ENCLAVE_CLOCK_SYNC_INTERVAL)
    );

    if let Err(e) = e3_api_result {
        log::error!("An error occurred within the E3 API server — {e:?}");
    }

    if let Err(e) = stats_result {
        log::error!("An error occurred within the stats proxy — {e:?}");
    }
}

#[cfg(feature = "network_egress")]
async fn start(data_plane_port: u16) {
    use data_plane::{crypto::api::CryptoApi, stats::StatsProxy};

    StatsClient::init();
    let context = match FeatureContext::get() {
        Ok(context) => context,
        Err(e) => {
            log::error!("Failed to access context in enclave - {e}");
            return;
        }
    };

    let (_, dns_result, e3_api_result, egress_result, stats_result, _) = tokio::join!(
        start_data_plane(data_plane_port, context.clone()),
        EnclaveDnsProxy::bind_server(context.egress.allow_list),
        CryptoApi::listen(),
        EgressProxy::listen(),
        StatsProxy::listen(),
        ClockSync::run(ENCLAVE_CLOCK_SYNC_INTERVAL)
    );

    if let Err(e) = dns_result {
        log::error!("An error occurred within the dns server — {e:?}");
    }

    if let Err(e) = egress_result {
        log::error!("An error occurred within the egress server — {e:?}");
    }

    if let Err(e) = e3_api_result {
        log::error!("An error occurred within the E3 API server — {e:?}");
    }

    if let Err(e) = stats_result {
        log::error!("An error occurred within the Stats proxy — {e:?}");
    }
}

#[allow(unused_variables)]
async fn start_data_plane(data_plane_port: u16, context: FeatureContext) {
    log::info!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match get_vsock_server_with_proxy_protocol(ENCLAVE_CONNECT_PORT, Enclave).await {
        Ok(server) => server,
        Err(error) => return log::error!("Error creating server: {error}"),
    };
    log::debug!("Data plane TCP server created");

    #[cfg(feature = "tls_termination")]
    {
        log::info!("TLS Termination enabled in dataplane. Running tls server.");
        data_plane::server::server::run(server, data_plane_port, context).await;
    }
    #[cfg(not(feature = "tls_termination"))]
    run_tcp_passthrough(server, data_plane_port).await;
}

#[cfg(not(feature = "tls_termination"))]
use shared::server::proxy_protocol::ProxiedConnection;
#[cfg(not(feature = "tls_termination"))]
async fn run_tcp_passthrough<L: Listener>(mut server: L, port: u16)
where
    <L as Listener>::Connection: ProxiedConnection + 'static,
{
    use shared::utils::pipe_streams;
    use tokio::io::AsyncWriteExt;
    log::info!("Piping TCP streams directly to user process");
    let should_forward_proxy_protocol = match FeatureContext::get() {
        Ok(context) => context.forward_proxy_protocol,
        Err(e) => {
            log::error!("Failed to access context in TCP Passthrough - {e}");
            return;
        }
    };

    let env_result = Environment::new().init_without_certs().await;
    if let Err(e) = env_result {
        log::error!(
            "An error occurred initializing the enclave environment — {:?}",
            e
        );
    }

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
            let mut customer_stream = match tokio::net::TcpStream::connect(("0.0.0.0", port)).await
            {
                Ok(customer_stream) => customer_stream,
                Err(e) => {
                    log::error!(
                        "An error occurred while connecting to the customer process — {}",
                        e
                    );
                    return;
                }
            };

            if incoming_conn.has_proxy_protocol() && should_forward_proxy_protocol {
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
