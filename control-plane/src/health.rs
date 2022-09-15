use crate::error::ServerError;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use shared::server::{error::ServerResult, tcp::TcpServer, Listener};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;

type HealthCheckServerState = Arc<Mutex<VecDeque<CombinedHealthCheckLog>>>;

pub struct HealthCheckServer {
    tcp_server: TcpServer,
    state: HealthCheckServerState,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
enum HealthCheckStatus {
    Ignored,
    Ok,
    Unknown,
    Err,
}

impl HealthCheckStatus {
    fn status_code(&self) -> u16 {
        match self {
            HealthCheckStatus::Ok | HealthCheckStatus::Ignored => 200,
            _ => 500,
        }
    }
}

impl std::fmt::Display for HealthCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use HealthCheckStatus::*;
        match self {
            Ignored => write!(f, "Ignored"),
            Ok => write!(f, "Ok"),
            Unknown => write!(f, "Unknown"),
            Err => write!(f, "Err"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: HealthCheckLog,
    data_plane: HealthCheckLog,
}

#[derive(Serialize, Deserialize, Debug)]
struct HealthCheckLog {
    status: HealthCheckStatus,
    message: Option<String>,
}

async fn run_ecs_health_check_service(
    state: HealthCheckServerState,
) -> std::result::Result<Response<Body>, ServerError> {
    let mut status_to_return = HealthCheckStatus::Ok;
    // This loop is empty for now. The data-plane health checks will populate this mutex in future.
    for CombinedHealthCheckLog { control_plane, .. } in state.lock().expect("Mutex poisoned").iter()
    {
        status_to_return = [
            status_to_return,
            control_plane.status.clone(),
            // data plane status can also be included here once data-plane health check is implemented
        ]
        .iter()
        .max()
        .unwrap()
        .clone();
    }
    Response::builder()
        .status(status_to_return.status_code())
        .header("Content-Type", "application/json")
        .body(Body::from(status_to_return.to_string()))
        .map_err(ServerError::from)
}

impl HealthCheckServer {
    pub async fn new() -> ServerResult<Self> {
        let tcp_server = TcpServer::bind(SocketAddr::from((
            [0, 0, 0, 0],
            CONTROL_PLANE_HEALTH_CHECK_PORT,
        )))
        .await?;
        Ok(HealthCheckServer {
            tcp_server,
            state: Default::default(),
        })
    }

    pub async fn start(&mut self) -> ServerResult<()> {
        println!(
            "Successfully started health check server on port {CONTROL_PLANE_HEALTH_CHECK_PORT}"
        );

        loop {
            let stream = self.tcp_server.accept().await?;
            let state = self.state.clone();
            let service = hyper::service::service_fn(move |request: Request<Body>| {
                let state = state.clone();
                async move {
                    match request
                        .headers()
                        .get("User-Agent")
                        .map(|value| value.as_bytes())
                    {
                        Some(b"ECS-HealthCheck") => run_ecs_health_check_service(state).await,
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

    #[tokio::test]
    async fn test_ecs_health_check_service_once() {
        let state: HealthCheckServerState = Default::default();
        let response = run_ecs_health_check_service(state).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_consecutive_ecs_health_check_service_calls() {
        // state should not change, so the health checks should keep passing
        let state: HealthCheckServerState = Default::default();
        let response = run_ecs_health_check_service(state.clone()).await.unwrap();
        assert_eq!(response.status(), 200);
        let response = run_ecs_health_check_service(state).await.unwrap();
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
