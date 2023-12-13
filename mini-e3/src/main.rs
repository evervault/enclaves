use hyper::{Request, Response, StatusCode};
use http_body_util::Full;
use shared::server::{get_vsock_server, Listener};
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
#[cfg(feature = "enclave")]
use tokio_vsock::VsockStream;

fn main() {
    println!("Hello, world!");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(start_server());
}

async fn start_server() {
    println!("Staring Server");

    try_update_fd_limit(65535, 65535);

    #[cfg(feature = "enclave")]
    let enclave_cid = shared::server::CID::Enclave;
    #[cfg(not(feature = "enclave"))]
    let enclave_cid = shared::server::CID::Local;

    let mut server = get_vsock_server(8001, enclave_cid)
        .await
        .unwrap();

    loop {
        let stream = server.accept().await.unwrap();
        #[cfg(feature = "enclave")]
        let io: TokioIo<tokio_vsock::VsockStream> = TokioIo::new(stream);

        #[cfg(not(feature = "enclave"))]
        let io: TokioIo<tokio::net::TcpStream> = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(hello))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

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

async fn hello(_: Request<impl hyper::body::Body>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut response_body = Response::new(Full::<Bytes>::from("Request recieved \n"));
    *response_body.status_mut() = StatusCode::OK;
    let response = response_body;

    Ok(response)
}
