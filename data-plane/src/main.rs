#[cfg(not(feature = "tls_termination"))]
use shared::server::Listener;
use shared::server::CID::Enclave;
use shared::{print_version, server::get_vsock_server_with_proxy_protocol};

#[cfg(not(feature = "tls_termination"))]
use data_plane::configuration;
#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;
#[cfg(not(feature = "tls_termination"))]
use data_plane::env::Environment;
use data_plane::health::start_health_check_server;
use data_plane::stats_client::StatsClient;
use data_plane::FeatureContext;
#[cfg(feature = "network_egress")]
use futures::future::join_all;
use shared::ENCLAVE_CONNECT_PORT;

#[tokio::main]
async fn main() {
    println!("Data plane running.");
    print_version!("Data Plane");

    let mut args = std::env::args();
    let _ = args.next(); // ignore path to executable
    let data_plane_port = args
        .next()
        .and_then(|port_str| port_str.as_str().parse::<u16>().ok())
        .unwrap_or(8008);

    tokio::join!(start(data_plane_port), start_health_check_server());
}

#[cfg(not(feature = "network_egress"))]
async fn start(data_plane_port: u16) {
    use data_plane::{crypto::api::CryptoApi, stats::StatsProxy};

    StatsClient::init();
    FeatureContext::set();
    println!("Running data plane with egress disabled");
    let (_, e3_api_result, stats_result) = tokio::join!(
        start_data_plane(data_plane_port),
        CryptoApi::listen(),
        StatsProxy::listen()
    );

    if let Err(e) = e3_api_result {
        eprintln!("An error occurred within the E3 API server — {e:?}");
    }

    if let Err(e) = stats_result {
        eprintln!("An error occurred within the stats proxy — {e:?}");
    }
}

#[cfg(feature = "network_egress")]
async fn start(data_plane_port: u16) {
    use data_plane::{crypto::api::CryptoApi, stats::StatsProxy};

    StatsClient::init();
    FeatureContext::set();
    let ports = FeatureContext::get().egress.ports;
    let egress_proxies = join_all(ports.into_iter().map(EgressProxy::listen));

    let (_, dns_result, e3_api_result, egress_results, stats_result) = tokio::join!(
        start_data_plane(data_plane_port),
        EnclaveDns::bind_server(),
        CryptoApi::listen(),
        egress_proxies,
        StatsProxy::listen()
    );

    if let Err(e) = dns_result {
        eprintln!("An error occurred within the dns server — {e:?}");
    }

    egress_results.into_iter().for_each(|egress_result| {
        if let Err(e) = egress_result {
            eprintln!("An error occurred within the egress server(s) — {e:?}");
        }
    });

    if let Err(e) = e3_api_result {
        eprintln!("An error occurred within the E3 API server — {e:?}");
    }

    if let Err(e) = stats_result {
        eprintln!("An error occurred within the Stats proxy — {e:?}");
    }
}

async fn start_data_plane(data_plane_port: u16) {
    println!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match get_vsock_server_with_proxy_protocol(ENCLAVE_CONNECT_PORT, Enclave).await {
        Ok(server) => server,
        Err(error) => return eprintln!("Error creating server: {error}"),
    };
    println!("Data plane TCP server created");

    #[cfg(feature = "tls_termination")]
    {
        println!("TLS Termination enabled in dataplane. Running tls server.");
        data_plane::server::data_plane_server::run(server, data_plane_port).await;
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
    println!("Piping TCP streams directly to user process");
    let should_forward_proxy_protocol = FeatureContext::get().forward_proxy_protocol;

    let env_result = Environment::new().init_without_certs().await;
    if let Err(e) = env_result {
        eprintln!(
            "An error occurred initializing the enclave environment — {:?}",
            e
        );
    }

    loop {
        let incoming_conn = match server.accept().await {
            Ok(incoming_conn) => incoming_conn,
            Err(e) => {
                eprintln!(
                    "An error occurred while accepting the incoming connection — {}",
                    e
                );
                continue;
            }
        };

        let mut customer_stream = match tokio::net::TcpStream::connect(("0.0.0.0", port)).await {
            Ok(customer_stream) => customer_stream,
            Err(e) => {
                eprintln!(
                    "An error occurred while connecting to the customer process — {}",
                    e
                );
                continue;
            }
        };

        if incoming_conn.has_proxy_protocol() && should_forward_proxy_protocol {
            // flush proxy protocol bytes to customer process
            let proxy_protocol = incoming_conn.proxy_protocol().unwrap();
            if let Err(e) = customer_stream.write_all(proxy_protocol.as_bytes()).await {
                eprintln!(
                    "An error occurred while forwarding the proxy protocol to the customer process — {}",
                    e
                );
                continue;
            }
        }

        if let Err(e) = pipe_streams(incoming_conn, customer_stream).await {
            eprintln!("An error occurred piping between the incoming connection and the customer process — {}", e);
            continue;
        }
    }
}
