#[cfg(feature = "enclave")]
use data_plane::crypto::attest;
use data_plane::error::AuthError;
use data_plane::error::Result;

use data_plane::server::tls::TlsServerBuilder;
use hyper::{Body, Request, Response};
#[cfg(not(feature = "enclave"))]
use shared::server::tcp::TcpServer;
use shared::server::Listener;

#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;

#[cfg(feature = "enclave")]
use shared::server::vsock::VsockServer;

const DATA_PLANE_PORT: u16 = 7777;

#[cfg(feature = "enclave")]
const ENCLAVE_CID: u32 = 2021;

use hyper::server::conn;
use hyper::service::service_fn;

use clap::Parser;

#[derive(Debug, Parser)]
struct DataPlaneArgs {
    /// Port to forward incoming traffic on
    #[clap(short, long, default_value = "8008")]
    port: u16,
}

#[tokio::main]
async fn main() {
    println!("Data plane running.");
    let args: DataPlaneArgs = DataPlaneArgs::parse();
    start(args).await
}

#[cfg(not(feature = "network_egress"))]
async fn start(args: DataPlaneArgs) {
    println!("Running data plane with egress disabled");
    start_data_plane(args).await;
}

#[cfg(feature = "network_egress")]
async fn start(args: DataPlaneArgs) {
    println!("Running data plane with egress enabled");
    let _ = tokio::join!(
        start_data_plane(args),
        EnclaveDns::bind_server(),
        EgressProxy::listen()
    );
}

async fn start_data_plane(args: DataPlaneArgs) {
    print!("Data plane starting on {}", DATA_PLANE_PORT);
    #[cfg(not(feature = "enclave"))]
    let get_server = TcpServer::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        DATA_PLANE_PORT,
    ))
    .await;

    #[cfg(feature = "enclave")]
    let get_server = VsockServer::bind(ENCLAVE_CID, DATA_PLANE_PORT.into()).await;

    let server = match get_server {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return;
        }
    };

    let tls_server_builder = TlsServerBuilder.with_server(server);
    let mut server = match tls_server_builder.with_self_signed_cert().await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return;
        }
    };

    let http_server = conn::Http::new();

    loop {
        if let Ok(stream) = server.accept().await {
            let server = http_server.clone();
            tokio::spawn(async move {
                let sent_response = server
                    .serve_connection(
                        stream,
                        service_fn(|req: Request<Body>| async move {
                            handle_incoming_request(req, args.port).await
                        }),
                    )
                    .await;

                if let Err(processing_err) = sent_response {
                    eprintln!(
                        "An error occurred while processing your request — {:?}",
                        processing_err
                    );
                }
            });
        }
    }
}

async fn handle_incoming_request(
    mut req: Request<Body>,
    customer_port: u16,
) -> Result<Response<Body>> {
    // Extract API Key header and authenticate request
    // Run parser over payload
    // Serialize request onto socket
    let _api_key_header = match req
        .headers_mut()
        .remove(hyper::http::header::HeaderName::from_static("api-key"))
        .ok_or(AuthError::NoApiKeyGiven)
    {
        Ok(api_key_header) => api_key_header,
        Err(e) => return Ok(e.into()),
    };

    // TODO: authenticate api key from request
    let (mut req_info, req_body) = req.into_parts();
    // TODO: find ciphertexts & decrypt
    // tmp: rename body to recreate request

    // Build processed request
    let decrypted_req_body = req_body;
    let mut uri_builder = hyper::Uri::builder()
        .authority(format!("0.0.0.0:{}", customer_port))
        .scheme("http");
    if let Some(req_path) = req_info.uri.path_and_query() {
        uri_builder = uri_builder.path_and_query(req_path.clone());
    }
    req_info.uri = uri_builder.build().expect("rebuilt from existing request");
    let decrypted_request = Request::from_parts(req_info, decrypted_req_body);

    let http_client = hyper::Client::new();
    let customer_response = match http_client.request(decrypted_request).await {
        Ok(res) => res,
        Err(e) => {
            let msg = format!("Error requesting customer process - {:?}", e);
            eprintln!("{}", msg);
            let res_body = Body::from(msg);
            Response::builder().status(500).body(res_body).unwrap()
        }
    };

    Ok(customer_response)
}
