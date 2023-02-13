use shared::print_version;
#[cfg(not(feature = "tls_termination"))]
use shared::server::Listener;

#[cfg(feature = "network_egress")]
use data_plane::configuration;
#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;
#[cfg(feature = "network_egress")]
use futures::future::join_all;

#[cfg(not(feature = "tls_termination"))]
use data_plane::env::Environment;
use data_plane::get_tcp_server;
use data_plane::health::start_health_check_server;
use shared::{env_var_present_and_true, ENCLAVE_CONNECT_PORT};

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

    if env_var_present_and_true!("DATA_PLANE_HEALTH_CHECKS") {
        tokio::join!(start(data_plane_port), start_health_check_server(),);
    } else {
        start(data_plane_port).await;
    }
}

#[cfg(not(feature = "network_egress"))]
async fn start(data_plane_port: u16) {
    use data_plane::crypto::api::CryptoApi;

    println!("Running data plane with egress disabled");
    let (_, e3_api_result) = tokio::join!(start_data_plane(data_plane_port), CryptoApi::listen());

    if let Err(e) = e3_api_result {
        eprintln!("An error occurred within the E3 API server — {e:?}");
    }
}

#[cfg(feature = "network_egress")]
async fn start(data_plane_port: u16) {
    use data_plane::crypto::api::CryptoApi;

    let ports = configuration::get_egress_ports();

    let egress_proxies = join_all(ports.into_iter().map(|port| EgressProxy::listen(port)));

    let (_, dns_result, e3_api_result, egress_results) = tokio::join!(
        start_data_plane(data_plane_port),
        EnclaveDns::bind_server(),
        CryptoApi::listen(),
        egress_proxies
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
}

async fn start_data_plane(data_plane_port: u16) {
    println!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match get_tcp_server(ENCLAVE_CONNECT_PORT).await {
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
async fn run_tcp_passthrough<L: Listener>(mut server: L, port: u16) {
    use shared::utils::pipe_streams;
    println!("Piping TCP streams directly to user process");

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

        let customer_stream = match tokio::net::TcpStream::connect(("0.0.0.0", port)).await {
            Ok(customer_stream) => customer_stream,
            Err(e) => {
                eprintln!(
                    "An error occurred while connecting to the customer process — {}",
                    e
                );
                continue;
            }
        };

        if let Err(e) = pipe_streams(incoming_conn, customer_stream).await {
            eprintln!("An error occurred piping between the incoming connection and the customer process — {}", e);
            continue;
        }
    }
}
