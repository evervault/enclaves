use crate::enclave_connection::get_connection_to_enclave;
use crate::error::ServerError;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::server::{error::ServerResult, tcp::TcpServer, Listener};
use shared::{env_var_present_and_true, ENCLAVE_HEALTH_CHECK_PORT};
use std::net::SocketAddr;

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;
#[derive(Clone)]
pub struct HealthCheckServerConfig {
    data_plane_checks_enabled: bool,
}

pub struct HealthCheckServer {
    tcp_server: TcpServer,
    config: HealthCheckServerConfig,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: HealthCheckLog,
    data_plane: HealthCheckLog,
}

async fn run_ecs_health_check_service(
    config: HealthCheckServerConfig,
) -> std::result::Result<Response<Body>, ServerError> {
    let control_plane = HealthCheckLog::new(
        HealthCheckStatus::Ok,
        Some("Control plane is running".into()),
    );

    let data_plane = if config.data_plane_checks_enabled {
        health_check_data_plane().await
    } else {
        HealthCheckLog::new(HealthCheckStatus::Ignored, None)
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
        let data_plane_checks_enabled = env_var_present_and_true!("DATA_PLANE_HEALTH_CHECKS");
        let tcp_server = TcpServer::bind(SocketAddr::from((
            [0, 0, 0, 0],
            CONTROL_PLANE_HEALTH_CHECK_PORT,
        )))
        .await?;
        Ok(HealthCheckServer {
            tcp_server,
            config: HealthCheckServerConfig {
                data_plane_checks_enabled,
            },
        })
    }

    pub async fn start(&mut self) -> ServerResult<()> {
        println!(
            "Control plane health-check server running on port {CONTROL_PLANE_HEALTH_CHECK_PORT}. Also checking data-plane: {}", self.config.data_plane_checks_enabled
        );

        loop {
            let stream = self.tcp_server.accept().await?;
            let config = self.config.clone();
            let service = hyper::service::service_fn(move |request: Request<Body>| {
                let config = config.clone();
                async move {
                    match request
                        .headers()
                        .get("User-Agent")
                        .map(|value| value.as_bytes())
                    {
                        Some(b"ECS-HealthCheck") => run_ecs_health_check_service(config).await,
                        _ => Response::builder()
                            .status(500)
                            .body(Body::from("Unsupported health check type!"))
                            .map_err(ServerError::from),
                    }
                }
            });
            if let Err(error) = hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(stream, service)
                .await
            {
                eprintln!("Health check error: {error}");
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
    async fn test_cage_health_check_service_deep() {
        // the data-plane status should error, as its not running
        let config = HealthCheckServerConfig {
            data_plane_checks_enabled: true,
        };
        let response = run_ecs_health_check_service(config).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;
        assert!(matches!(
            health_check_log.data_plane.status,
            HealthCheckStatus::Err
        ));
    }

    #[tokio::test]
    async fn test_cage_health_check_service_shallow() {
        // the health check should succeed, as the data-plane isn't checked
        let config = HealthCheckServerConfig {
            data_plane_checks_enabled: false,
        };
        let response = run_ecs_health_check_service(config).await.unwrap();
        assert_eq!(response.status(), 200);
        println!("shallow response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;
        assert!(matches!(
            health_check_log.data_plane.status,
            HealthCheckStatus::Ignored
        ));
    }

    #[tokio::test]
    async fn test_consecutive_ecs_health_check_service_calls() {
        // state should not change, so the health checks should keep passing
        let config = HealthCheckServerConfig {
            data_plane_checks_enabled: false,
        };
        let response = run_ecs_health_check_service(config.clone()).await.unwrap();
        assert_eq!(response.status(), 200);
        let response = run_ecs_health_check_service(config).await.unwrap();
        assert_eq!(response.status(), 200);
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
