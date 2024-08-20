use crate::enclave_connection::get_connection_to_enclave;
use crate::error::ServerError;
use axum::http::HeaderValue;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use shared::server::{
    error::ServerResult,
    health::{ControlPlaneState, DataPlaneState, HealthCheck, HealthCheckLog, HealthCheckVersion},
    tcp::TcpServer,
    Listener,
};
use shared::ENCLAVE_HEALTH_CHECK_PORT;
use std::net::SocketAddr;
use std::sync::OnceLock;

pub static IS_DRAINING: OnceLock<bool> = OnceLock::new();

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;

pub struct HealthCheckServer {
    tcp_server: TcpServer,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: ControlPlaneState,
    data_plane: HealthCheckVersion,
}

pub async fn run_ecs_health_check_service(
    is_draining: bool,
) -> std::result::Result<Response<Body>, ServerError> {
    if is_draining {
        let combined_log = CombinedHealthCheckLog {
            control_plane: ControlPlaneState::Draining,
            data_plane: HealthCheckVersion::V1(DataPlaneState::Unknown(
                "Enclave is draining, data-plane health will not be checked".into(),
            )),
        };

        let combined_log_json = serde_json::to_string(&combined_log)?;

        return Ok(Response::builder()
            .status(500)
            .header("Content-Type", "application/json")
            .body(Body::from(combined_log_json))?);
    };

    let control_plane = ControlPlaneState::Ok;

    let data_plane = match health_check_data_plane().await {
        Ok(state) => state,
        Err(e) => HealthCheckVersion::V1(DataPlaneState::Unknown(format!(
            "Failed to contact data-plane for healthcheck: {e}"
        ))),
    };

    let data_plane_status_code = match &data_plane {
        HealthCheckVersion::V0(log) => log.status_code(),
        HealthCheckVersion::V1(data_plane_state) => data_plane_state.status_code(),
    };

    let status_to_return = std::cmp::max(control_plane.status_code(), data_plane_status_code);

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

type EcsHealthCheckResult = Result<HealthCheckVersion, ServerError>;

async fn health_check_data_plane() -> EcsHealthCheckResult {
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
            HealthCheckVersion::V1(serde_json::from_slice::<DataPlaneState>(bytes)?)
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
                        run_ecs_health_check_service(is_draining).await
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
        let response = run_ecs_health_check_service(false).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        let dp_state = match health_check_log.data_plane {
            HealthCheckVersion::V1(log) => log,
            _ => panic!("Expected V1 log"),
        };

        assert!(matches!(dp_state, DataPlaneState::Unknown(_)));
    }

    #[tokio::test]
    async fn test_enclave_health_check_service_with_draining_set_to_true() {
        // the data-plane status should error, as its not running
        IS_DRAINING.set(true).unwrap();
        let response = run_ecs_health_check_service(true).await.unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        let dp_state = match health_check_log.data_plane {
            HealthCheckVersion::V1(log) => log,
            _ => panic!("Expected V1 log"),
        };

        assert!(matches!(dp_state, DataPlaneState::Unknown(_)));
        assert!(matches!(
            health_check_log.control_plane,
            ControlPlaneState::Draining
        ));
    }
}
