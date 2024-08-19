use crate::enclave_connection::get_connection_to_enclave;
use crate::error::ServerError;
use axum::http::HeaderValue;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use shared::server::health::{HealthCheckLog, HealthCheckStatus, HealthCheckVersion};
use shared::server::{error::ServerResult, tcp::TcpServer, Listener};
use shared::{env_var_present_and_true, ENCLAVE_HEALTH_CHECK_PORT};
use std::net::SocketAddr;
use std::sync::OnceLock;

pub static IS_DRAINING: OnceLock<bool> = OnceLock::new();

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;

pub struct HealthCheckServer {
    tcp_server: TcpServer,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: HealthCheckLog,
    data_plane: HealthCheckVersion,
}

async fn run_ecs_health_check_service(
    skip_deep_healthcheck: bool,
    is_draining: bool,
) -> std::result::Result<Response<Body>, ServerError> {
    if is_draining {
        let draining_log =
            HealthCheckLog::new(HealthCheckStatus::Err, Some("Enclave is draining".into()));

        let combined_log = CombinedHealthCheckLog {
            control_plane: draining_log.clone(),
            data_plane: HealthCheckVersion::V1(draining_log),
        };

        let combined_log_json = serde_json::to_string(&combined_log)?;

        return Ok(Response::builder()
            .status(500)
            .header("Content-Type", "application/json")
            .body(Body::from(combined_log_json))?);
    };

    let control_plane = HealthCheckLog::new(
        HealthCheckStatus::Ok,
        Some("Control plane is running".into()),
    );

    let data_plane = if skip_deep_healthcheck {
        HealthCheckVersion::V1(HealthCheckLog::new(HealthCheckStatus::Ignored, None))
    } else {
        health_check_data_plane().await?
    };

    let data_plane_status = match &data_plane {
        HealthCheckVersion::V0(log) => log.status_code(),
        HealthCheckVersion::V1(log) => log.status_code(),
    };

    let status_to_return = std::cmp::max(control_plane.status_code(), data_plane_status);

    let combined_log = CombinedHealthCheckLog {
        control_plane,
        data_plane,
    };
    let combined_log_json = serde_json::to_string(&combined_log).unwrap();

    Response::builder()
        .status(status_to_return)
        .header("Content-Type", "application/json")
        .body(Body::from(combined_log_json))
        .map_err(ServerError::from)
}

async fn health_check_data_plane() -> Result<HealthCheckVersion, ServerError> {
    let stream = get_connection_to_enclave(ENCLAVE_HEALTH_CHECK_PORT).await?;

    let (mut sender, connection) = hyper::client::conn::handshake(stream).await?;

    tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .header("User-Agent", "CageHealthChecker/0.0")
        .body(Body::empty())
        .expect("Cannot fail");

    let response = sender.send_request(request).await?;
    let (parts, response) = response.into_parts();

    let content_type = parts
        .headers
        .get("Content-Type")
        .map(HeaderValue::to_str)
        .and_then(Result::ok);

    let bytes = &hyper::body::to_bytes(response).await?;

    Ok(match content_type {
        Some("application/json;version=1") => {
            HealthCheckVersion::V1(serde_json::from_slice::<HealthCheckLog>(bytes)?)
        }
        _ => HealthCheckVersion::V0(serde_json::from_slice::<HealthCheckLog>(bytes)?),
    })
}

impl HealthCheckServer {
    pub async fn new() -> ServerResult<Self> {
        let tcp_server = TcpServer::bind(SocketAddr::from((
            [0, 0, 0, 0],
            CONTROL_PLANE_HEALTH_CHECK_PORT,
        )))
        .await?;
        Ok(HealthCheckServer { tcp_server })
    }

    pub async fn start(&mut self) -> ServerResult<()> {
        log::info!(
            "Control plane health-check server running on port {CONTROL_PLANE_HEALTH_CHECK_PORT}"
        );

        // Perform deep healthchecks into the enclave *unless* `DISABLE_DEEP_HEALTH_CHECKS` is set to "true"
        let skip_deep_healthcheck = env_var_present_and_true!("DISABLE_DEEP_HEALTH_CHECKS");

        loop {
            let stream = self.tcp_server.accept().await?;
            let service = hyper::service::service_fn(move |request: Request<Body>| async move {
                match request
                    .headers()
                    .get("User-Agent")
                    .map(|value| value.as_bytes())
                {
                    Some(b"ECS-HealthCheck") => {
                        let is_draining = IS_DRAINING.get().is_some();
                        run_ecs_health_check_service(skip_deep_healthcheck, is_draining).await
                    }
                    _ => Response::builder()
                        .status(400)
                        .body(Body::from("Unsupported health check type!"))
                        .map_err(ServerError::from),
                }
            });
            if let Err(error) = hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(stream, service)
                .await
            {
                log::error!("Health check error: {error}");
            }
        }
    }
}

#[cfg(test)]
mod health_check_tests {
    use super::*;

    async fn response_to_health_check_log(response: Response<Body>) -> CombinedHealthCheckLog {
        let response_body = response.into_body();
        let response_body = hyper::body::to_bytes(response_body).await.unwrap();
        serde_json::from_slice(&response_body).unwrap()
    }

    #[tokio::test]
    async fn test_enclave_health_check_service() {
        // the data-plane status should error, as its not running
        let response = run_ecs_health_check_service(false, false).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        let dp_status = match health_check_log.data_plane {
            HealthCheckVersion::V0(log) => log.status,
            HealthCheckVersion::V1(log) => log.status,
        };

        assert!(matches!(dp_status, HealthCheckStatus::Err));
    }

    #[tokio::test]
    async fn test_enclave_health_check_service_with_skip_deep_set_to_true() {
        // the data-plane status should error, as its not running
        let response = run_ecs_health_check_service(true, false).await.unwrap();
        assert_eq!(response.status(), 200);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        let dp_status = match health_check_log.data_plane {
            HealthCheckVersion::V0(log) => log.status,
            HealthCheckVersion::V1(log) => log.status,
        };

        assert!(matches!(dp_status, HealthCheckStatus::Ignored));
    }

    #[tokio::test]
    async fn test_enclave_health_check_service_with_draining_set_to_true() {
        // the data-plane status should error, as its not running
        IS_DRAINING.set(true).unwrap();
        let response = run_ecs_health_check_service(false, true).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        let dp_status = match health_check_log.data_plane {
            HealthCheckVersion::V0(log) => log.status,
            HealthCheckVersion::V1(log) => log.status,
        };

        assert!(matches!(dp_status, HealthCheckStatus::Err));
        assert!(matches!(
            health_check_log.control_plane.status,
            HealthCheckStatus::Err
        ));
    }

    #[tokio::test]
    async fn test_max_of_enum() {
        // used in run_ecs_health_check_service to ensure non-success codes have priority
        let max = [
            HealthCheckStatus::Err,
            HealthCheckStatus::Ok,
            HealthCheckStatus::Unknown,
            HealthCheckStatus::Ignored,
        ]
        .iter()
        .max()
        .unwrap();
        assert!(matches!(max, HealthCheckStatus::Err));
        let max = [
            HealthCheckStatus::Ok,
            HealthCheckStatus::Unknown,
            HealthCheckStatus::Ignored,
        ]
        .iter()
        .max()
        .unwrap();
        assert!(matches!(max, HealthCheckStatus::Unknown));
    }
}
