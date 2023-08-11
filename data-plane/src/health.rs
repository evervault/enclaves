use std::fs;

use hyper::{Body, Request, Response};
use shared::server::get_vsock_server;
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::server::CID::Enclave;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};

use log::{info, error};

pub async fn start_health_check_server() {
    let mut health_check_server = get_vsock_server(ENCLAVE_HEALTH_CHECK_PORT, Enclave)
        .await
        .unwrap();
    info!("Data plane health check server running on port {ENCLAVE_HEALTH_CHECK_PORT}");

    loop {
        let stream = match health_check_server.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Error accepting health check request — {e:?}");
                continue;
            }
        };
        let service = hyper::service::service_fn(move |_: Request<Body>| async move {
            match fs::read_to_string("/etc/customer-env") {
                Ok(contents) => {
                    if contents.contains("EV_CAGE_INITIALIZED") {
                        let response = HealthCheckLog {
                            message: Some("Hello from the data-plane".into()),
                            status: HealthCheckStatus::Ok,
                        };

                        Response::builder()
                            .status(200)
                            .body(Body::from(serde_json::to_string(&response).unwrap()))
                    } else {
                        error_response()
                    }
                }
                Err(_) => error_response(),
            }
        });

        if let Err(error) = hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(stream, service)
            .await
        {
            error!("Data plane health check error: {error}");
        }
    }

    fn error_response() -> Result<Response<Body>, hyper::http::Error> {
        let response = HealthCheckLog {
            message: Some("Cage environment is not yet initialized".into()),
            status: HealthCheckStatus::Uninitialized,
        };

        Response::builder()
            .status(500)
            .body(Body::from(serde_json::to_string(&response).unwrap()))
    }
}
