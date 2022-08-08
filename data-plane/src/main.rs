use serde::{Deserialize, Serialize};

use data_plane::crypto;
#[cfg(feature = "enclave")]
use data_plane::crypto::attest;
use data_plane::error::AuthError;
use data_plane::error::Result;

use data_plane::server::{http::ContentEncoding, tls::TlsServerBuilder};

use hyper::http::{self, request::Parts};
use hyper::{Body, Request, Response};
use nom::AsBytes;
#[cfg(not(feature = "enclave"))]
use shared::server::tcp::TcpServer;
use shared::server::Listener;

#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(feature = "network_egress")]
use data_plane::dns::egressproxy::EgressProxy;
#[cfg(feature = "network_egress")]
use data_plane::dns::enclavedns::EnclaveDns;

use shared::ENCLAVE_CONNECT_PORT;
#[cfg(feature = "enclave")]
use shared::{server::vsock::VsockServer, ENCLAVE_CID};

use futures::StreamExt;
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
    let (_, dns_result, egress_result) = tokio::join!(
        start_data_plane(args),
        EnclaveDns::bind_server(),
        EgressProxy::listen()
    );

    if let Err(e) = dns_result {
        eprintln!("An error occurred within the dns server — {:?}", e);
    }

    if let Err(e) = egress_result {
        eprintln!("An error occurred within the egress server — {:?}", e);
    }
}

#[cfg(not(feature = "enclave"))]
async fn get_server() -> std::result::Result<TcpServer, shared::server::error::ServerError> {
    println!("Creating tcp server");
    TcpServer::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        ENCLAVE_CONNECT_PORT,
    ))
    .await
}

#[cfg(feature = "enclave")]
async fn get_server() -> std::result::Result<VsockServer, shared::server::error::ServerError> {
    println!("Creating VSock server");
    VsockServer::bind(ENCLAVE_CID, ENCLAVE_CONNECT_PORT.into()).await
}

async fn start_data_plane(args: DataPlaneArgs) {
    print!("Data plane starting on {}", ENCLAVE_CONNECT_PORT);
    let server_result = get_server().await;
    let server = match server_result {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error creating server: {:?}", e);
            return;
        }
    };

    println!("Data plane server started successfully");
    let tls_server_builder = TlsServerBuilder.with_server(server);
    let mut server = match tls_server_builder.with_self_signed_cert().await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Error creating tls server with self signed cert — {:?}", e);
            return;
        }
    };

    println!("TLS upgrade complete");
    let http_server = conn::Http::new();

    loop {
        let stream = match server.accept().await {
            Ok(stream) => stream,
            Err(tls_err) => {
                eprintln!(
                    "An error occurred while accepting the incoming connection — {:?}",
                    tls_err
                );
                continue;
            }
        };
        let server = http_server.clone();
        tokio::spawn(async move {
            println!("Accepted tls connection");
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

async fn handle_incoming_request(
    mut req: Request<Body>,
    customer_port: u16,
) -> Result<Response<Body>> {
    // Extract API Key header and authenticate request
    // Run parser over payload
    // Serialize request onto socket
    let api_key = match req
        .headers_mut()
        .remove(hyper::http::header::HeaderName::from_static("api-key"))
        .ok_or(AuthError::NoApiKeyGiven)
    {
        Ok(api_key_header) => api_key_header,
        Err(e) => return Ok(e.into()),
    };

    println!("Extracted API key from request");
    // TODO: authenticate api key from request
    let (req_info, req_body) = req.into_parts();

    let compression = req_info
        .headers
        .get(http::header::CONTENT_ENCODING)
        .map(ContentEncoding::try_from)
        .map(|encoding_res| encoding_res.ok())
        .flatten();

    if let Some(_encoding) = req_info.headers.get(http::header::TRANSFER_ENCODING) {
        Ok(Response::builder().status(500).body(Body::empty()).unwrap())
    } else {
        handle_standard_request(api_key, req_info, req_body, compression, customer_port).await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedDataEntry {
    range: (usize, usize),
    value: String,
}

impl EncryptedDataEntry {
    #[allow(unused)]
    pub fn range(&self) -> (usize, usize) {
        self.range
    }

    #[allow(unused)]
    pub fn value(&self) -> &str {
        &self.value
    }
}

// Handler for incoming requests which are not chunked
async fn handle_standard_request(
    _api_key: hyper::header::HeaderValue,
    mut req_info: Parts,
    req_body: Body,
    _compression: Option<ContentEncoding>,
    customer_port: u16,
) -> Result<Response<Body>> {
    let request_bytes = match hyper::body::to_bytes(req_body).await {
        Ok(body_bytes) => body_bytes,
        Err(e) => {
            eprintln!("Failed to read entire body — {}", e);
            return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
        }
    };

    let mut stream_reader =
        crypto::stream::IncomingStreamDecoder::create_reader(request_bytes.as_bytes());

    let mut decryption_payload = vec![];
    while let Some(parsed_frame) = stream_reader.next().await {
        let (range, ciphertext) = match parsed_frame {
            Ok(crypto::stream::IncomingFrame::Ciphertext(ciphertext)) => ciphertext,
            Ok(_) => continue,
            Err(e) => {
                eprintln!("An error while decoding the incoming request — {:?}", e);
                return Ok(Response::builder().status(500).body(Body::empty()).unwrap());
            }
        };

        let ciphertext_item = serde_json::json!({
            "range": [range.0, range.1],
            "value": ciphertext.to_string()
        });
        decryption_payload.push(ciphertext_item);
    }

    println!("Ciphertexts extracted: {:?}", decryption_payload);

    let bytes_vec = request_bytes.to_vec();

    // Build processed request
    let mut uri_builder = hyper::Uri::builder()
        .authority(format!("0.0.0.0:{}", customer_port))
        .scheme("http");
    if let Some(req_path) = req_info.uri.path_and_query() {
        uri_builder = uri_builder.path_and_query(req_path.clone());
    }
    req_info.uri = uri_builder.build().expect("rebuilt from existing request");
    let decrypted_request = Request::from_parts(req_info, Body::from(bytes_vec));
    println!("Finished processing request");
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
    println!("Response received from customer");

    Ok(customer_response)
}
