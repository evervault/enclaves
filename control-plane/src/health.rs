use crate::enclave_connection::get_connection_to_enclave;
use crate::error::ServerError;
use hyper::{Body, Request, Response};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::server::{error::ServerResult, tcp::TcpServer, Listener};
use shared::{env_var_present_and_true, ENCLAVE_HEALTH_CHECK_PORT};
use std::net::SocketAddr;
use tokio::sync::Mutex;

lazy_static! {
    static ref IS_DRAINING: Mutex<bool> = Mutex::new(false);
}

pub async fn set_draining(value: bool) {
    let mut bool_guard = IS_DRAINING.lock().await;
    *bool_guard = value;
}

async fn is_draining() -> bool {
    let bool_guard = IS_DRAINING.lock().await;
    *bool_guard
}

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;

pub struct HealthCheckServer {
    tcp_server: TcpServer,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: HealthCheckLog,
    data_plane: HealthCheckLog,
}

async fn run_ecs_health_check_service(
    skip_deep_healthcheck: bool,
) -> std::result::Result<Response<Body>, ServerError> {
    if is_draining().await {
        let draining_log =
            HealthCheckLog::new(HealthCheckStatus::Err, Some("Cage is draining".into()));

        let combined_log = CombinedHealthCheckLog {
            control_plane: draining_log.clone(),
            data_plane: draining_log,
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
        HealthCheckLog::new(HealthCheckStatus::Ignored, None)
    } else {
        health_check_data_plane().await
    };
    let status_to_return = [control_plane.status.clone(), data_plane.status.clone()]
        .iter()
        .max()
        .unwrap()
        .clone();

    let combined_log = CombinedHealthCheckLog {
        control_plane,
        data_plane,
    };
    let combined_log_json = serde_json::to_string(&combined_log).unwrap();

    Response::builder()
        .status(status_to_return.status_code())
        .header("Content-Type", "application/json")
        .body(Body::from(combined_log_json))
        .map_err(ServerError::from)
}

macro_rules! unwrap_or_err {
    ($result:expr) => {
        match $result {
            Ok(ok) => ok,
            Err(error) => {
                return HealthCheckLog::new(HealthCheckStatus::Err, Some(error.to_string()))
            }
        }
    };
}

async fn health_check_data_plane() -> HealthCheckLog {
    let stream = unwrap_or_err!(get_connection_to_enclave(ENCLAVE_HEALTH_CHECK_PORT).await);
    let (mut sender, connection) = unwrap_or_err!(hyper::client::conn::handshake(stream).await);
    tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .header("User-Agent", "CageHealthChecker/0.0")
        .body(Body::empty())
        .expect("Cannot fail");
    let response = unwrap_or_err!(sender.send_request(request).await);
    unwrap_or_err!(serde_json::from_slice(
        &hyper::body::to_bytes(response.into_parts().1)
            .await
            .unwrap()[..]
    ))
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
                        run_ecs_health_check_service(skip_deep_healthcheck).await
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
    async fn test_cage_health_check_service() {
        // the data-plane status should error, as its not running
        set_draining(false).await;
        let response = run_ecs_health_check_service(false).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;
        assert!(matches!(
            health_check_log.data_plane.status,
            HealthCheckStatus::Err
        ));
    }

    #[tokio::test]
    async fn test_cage_health_check_service_with_skip_deep_set_to_true() {
        // the data-plane status should error, as its not running
        set_draining(false).await;
        let response = run_ecs_health_check_service(true).await.unwrap();
        assert_eq!(response.status(), 200);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;
        assert!(matches!(
            health_check_log.data_plane.status,
            HealthCheckStatus::Ignored
        ));
    }

    #[tokio::test]
    async fn test_cage_health_check_service_with_draining_set_to_true() {
        // the data-plane status should error, as its not running
        set_draining(true).await;
        let response = run_ecs_health_check_service(false).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;
        assert!(matches!(
            health_check_log.data_plane.status,
            HealthCheckStatus::Err
        ));
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
