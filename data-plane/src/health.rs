use crate::get_tcp_server;
use hyper::{Body, Request, Response};
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};

pub async fn start_health_check_server() {
    let mut health_check_server = get_tcp_server(ENCLAVE_HEALTH_CHECK_PORT).await.unwrap();
    println!("Data plane health check server running on port {ENCLAVE_HEALTH_CHECK_PORT}");

    loop {
        let stream = match health_check_server.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Error accepting health check request — {e:?}");
                continue;
            }
        };
        let service = hyper::service::service_fn(move |_: Request<Body>| async move {
            let response = HealthCheckLog {
                message: Some("Hello from the data-plane".into()),
                status: HealthCheckStatus::Ok,
            };

            Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_string(&response).unwrap()))
        });
        if let Err(error) = hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(stream, service)
            .await
        {
            eprintln!("Data plane health check error: {error}");
        }
    }
}
