use std::fs;

use hyper::{Body, Request, Response};
use shared::server::get_vsock_server;
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::server::CID::Enclave;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};

use crate::cache::TRUSTED_CERT_STORE;

pub async fn start_health_check_server() {
    let mut health_check_server = get_vsock_server(ENCLAVE_HEALTH_CHECK_PORT, Enclave)
        .await
        .unwrap();
    log::info!("Data plane health check server running on port {ENCLAVE_HEALTH_CHECK_PORT}");

    loop {
        let stream = match health_check_server.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                log::error!("Error accepting health check request — {e:?}");
                continue;
            }
        };
        let service = hyper::service::service_fn(move |_: Request<Body>| async {
            match fs::read_to_string("/etc/customer-env") {
                Ok(contents) => {
                    match (
                        contents.contains("EV_CAGE_INITIALIZED"),
                        contents.contains("EV_CAGE_CERT_READY"),
                    ) {
                        (true, true) => ok_response(),
                        (true, false) => check_for_trusted_cert_timeout(),
                        _ => error_response(),
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
            log::error!("Data plane health check error: {error}");
        }
    }

    fn check_for_trusted_cert_timeout() -> Result<Response<Body>, hyper::http::Error> {
        let now = chrono::Utc::now();

        match TRUSTED_CERT_STORE.read() {
            Ok(store) => match store.get_initialized_time() {
                Some(time) if now.signed_duration_since(time).num_minutes() < 3 => ok_response(),
                _ => error_response(),
            },
            Err(err) => {
                log::error!("Error reading cage initialized time from store: {}", err);
                error_response()
            }
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

    fn ok_response() -> Result<Response<Body>, hyper::http::Error> {
        let response = HealthCheckLog {
            message: Some("Hello from the data-plane".into()),
            status: HealthCheckStatus::Ok,
        };

        Response::builder()
            .status(200)
            .body(Body::from(serde_json::to_string(&response).unwrap()))
    }
}
