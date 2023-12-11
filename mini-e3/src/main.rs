use hyper::{Request, Response};
use http_body_util::Full;
use shared::server::{get_vsock_server, Listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper::service::{service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::convert::Infallible;
use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
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

    let mut server = get_vsock_server(8001, shared::server::CID::Enclave)
        .await
        .unwrap();


    loop {
        let stream = server.accept().await.unwrap();

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        // let io = TokioIo::new(stream);
        let io: TokioIo<tokio_vsock::VsockStream> = TokioIo::new(stream);
        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(hello))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn hello(_: Request<impl hyper::body::Body>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello World!"))))
}
