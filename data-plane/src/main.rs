use shared::print_version;
#[cfg(not(feature = "tls_termination"))]
use shared::server::Listener;

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;

use data_plane::health::start_health_check_server;
use data_plane::{configuration, get_tcp_server};
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
        eprintln!("An error occurred within the E3 API server — {:?}", e);
    }
}

#[cfg(feature = "network_egress")]
async fn start(data_plane_port: u16) {
    use data_plane::crypto::api::CryptoApi;

    println!("Running data plane with egress enabled");
    let (_, dns_result, egress_result, e3_api_result) = tokio::join!(
        start_data_plane(data_plane_port),
        EnclaveDns::bind_server(),
        EgressProxy::listen(),
        CryptoApi::listen()
    );

    if let Err(e) = dns_result {
        eprintln!("An error occurred within the dns server — {:?}", e);
    }

    if let Err(e) = egress_result {
        eprintln!("An error occurred within the egress server — {:?}", e);
    }

    if let Err(e) = e3_api_result {
        eprintln!("An error occurred within the E3 API server — {:?}", e);
    }
}

async fn start_data_plane(data_plane_port: u16) {
    println!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match get_tcp_server(ENCLAVE_CONNECT_PORT).await {
        Ok(server) => server,
        Err(error) => return eprintln!("Error creating server: {error}"),
    };
    println!("Data plane TCP server created");

    let auth_enabled = configuration::api_key_auth_enabled();

    #[cfg(feature = "tls_termination")]
    {
        println!("TLS Termination enabled in dataplane. Running tls server.");
        data_plane::server::data_plane_server::run(server, data_plane_port, auth_enabled).await;
    }
    #[cfg(not(feature = "tls_termination"))]
    run_tcp_passthrough(server, data_plane_port).await;
}

#[cfg(not(feature = "tls_termination"))]
async fn run_tcp_passthrough<L: Listener>(mut server: L, port: u16) {
    use shared::utils::pipe_streams;
    println!("Piping TCP streams directly to user process");
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
