use crate::error::ServerError;
use axum::http::HeaderValue;
use hyper::{Body, Request, Response};
use log::Level;
use serde::{Deserialize, Serialize};
use shared::notify_shutdown::Service;
use shared::server::{
    error::ServerResult,
    health::{
        ControlPlaneState, DataPlaneState, EnclaveIdentity, HealthCheck, HealthCheckLog,
        HealthCheckVersion,
    },
    tcp::TcpServer,
    Listener,
};
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    ENCLAVE_HEALTH_CHECK_PORT,
};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc::Receiver;

pub static IS_DRAINING: OnceLock<bool> = OnceLock::new();

pub fn is_draining() -> bool {
    IS_DRAINING.get().is_some()
}

pub const CONTROL_PLANE_HEALTH_CHECK_PORT: u16 = 3032;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CombinedHealthCheckLog {
    control_plane: ControlPlaneState,
    data_plane: HealthCheckVersion,
    enclave: EnclaveIdentity,
}

pub async fn run_ecs_health_check_service(
    is_draining: bool,
    control_plane_state: ControlPlaneState,
    enclave: &EnclaveIdentity,
) -> std::result::Result<Response<Body>, ServerError> {
    if is_draining {
        let combined_log = CombinedHealthCheckLog {
            control_plane: ControlPlaneState::Draining,
            data_plane: DataPlaneState::Unknown(
                "Enclave is draining, data-plane health will not be checked".into(),
            )
            .into(),
            enclave: enclave.clone(),
        };

        let combined_log_json = serde_json::to_string(&combined_log)?;

        return Ok(Response::builder()
            .status(500)
            .header("Content-Type", "application/json")
            .body(Body::from(combined_log_json))?);
    };

    let data_plane = health_check_data_plane().await.unwrap_or_else(|e| {
        DataPlaneState::Error(format!("Failed to contact data-plane for healthcheck: {e}")).into()
    });

    let status_to_return =
        std::cmp::max(control_plane_state.status_code(), data_plane.status_code());

    let combined_log = CombinedHealthCheckLog {
        control_plane: control_plane_state,
        data_plane,
        enclave: enclave.clone(),
    };

    let level = if status_to_return == 200 {
        Level::Info
    } else {
        Level::Error
    };
    log::log!(
        level,
        "{}",
        serde_json::json!({
            "event": "health_check",
            "status": status_to_return,
            "result": combined_log,
        })
    );

    Response::builder()
        .status(status_to_return)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&combined_log)?))
        .map_err(ServerError::from)
}

async fn health_check_data_plane() -> Result<HealthCheckVersion, ServerError> {
    let stream =
        Bridge::get_client_connection(ENCLAVE_HEALTH_CHECK_PORT, Direction::HostToEnclave).await?;

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

    let hc = match content_type {
        Some("application/json;version=1") => {
            HealthCheckVersion::V1(serde_json::from_slice::<DataPlaneState>(bytes)?)
        }
        _ => HealthCheckVersion::V0(serde_json::from_slice::<HealthCheckLog>(bytes)?),
    };

    Ok(hc)
}

pub struct HealthCheckServer {
    shutdown_receiver: Receiver<Service>,
    exited_services: Vec<Service>,
    enclave_identity: Arc<EnclaveIdentity>,
}

impl HealthCheckServer {
    pub fn new(shutdown_receiver: Receiver<Service>, enclave_identity: EnclaveIdentity) -> Self {
        Self {
            shutdown_receiver,
            exited_services: Vec::new(),
            enclave_identity: Arc::new(enclave_identity),
        }
    }

    pub async fn start(&mut self) -> ServerResult<()> {
        log::info!(
            "Control plane health-check server running on port {CONTROL_PLANE_HEALTH_CHECK_PORT}"
        );

        let mut tcp_server = TcpServer::bind(SocketAddr::from((
            [0, 0, 0, 0],
            CONTROL_PLANE_HEALTH_CHECK_PORT,
        )))
        .await?;

        loop {
            let stream = tcp_server.accept().await?;

            let cp_state = self.get_control_plane_state();

            let service = hyper::service::service_fn({
                let cp_state = cp_state.clone();
                let enclave_identity = Arc::clone(&self.enclave_identity);
                move |request: Request<Body>| {
                    let cp_state = cp_state.clone();
                    let enclave_identity = Arc::clone(&enclave_identity);
                    async move {
                        match request
                            .headers()
                            .get("User-Agent")
                            .map(|value| value.as_bytes())
                        {
                            Some(b"ECS-HealthCheck") => {
                                run_ecs_health_check_service(
                                    is_draining(),
                                    cp_state,
                                    &enclave_identity,
                                )
                                .await
                            }
                            _ => Response::builder()
                                .status(400)
                                .body(Body::from("Unsupported health check type!"))
                                .map_err(ServerError::from),
                        }
                    }
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

    fn get_control_plane_state(&mut self) -> ControlPlaneState {
        if let Ok(exited_service) = self.shutdown_receiver.try_recv() {
            self.exited_services.push(exited_service);
            ControlPlaneState::Error(format!(
                "Critical Control Plane services have exited: {}",
                self.serialize_exited_services()
            ))
        } else if !self.exited_services.is_empty() {
            ControlPlaneState::Error(format!(
                "Critical Control Plane services have exited: {}",
                self.serialize_exited_services()
            ))
        } else {
            ControlPlaneState::Ok
        }
    }

    fn serialize_exited_services(&self) -> String {
        self.exited_services
            .iter()
            .map(|service| service.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod health_check_tests {
    use super::*;

    fn test_identity() -> EnclaveIdentity {
        EnclaveIdentity {
            app_uuid: "app_123".into(),
            team_uuid: "team_456".into(),
            enclave_uuid: "enclave_789".into(),
            name: "my-enclave".into(),
        }
    }

    async fn response_to_health_check_log(response: Response<Body>) -> CombinedHealthCheckLog {
        let response_body = response.into_body();
        let response_body = hyper::body::to_bytes(response_body).await.unwrap();
        serde_json::from_slice(&response_body).unwrap()
    }

    #[tokio::test]
    async fn test_enclave_health_check_service() {
        // the data-plane status should error, as its not running
        let response = run_ecs_health_check_service(false, ControlPlaneState::Ok, &test_identity())
            .await
            .unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        assert_eq!(health_check_log.enclave, test_identity());

        let dp_state = match health_check_log.data_plane {
            HealthCheckVersion::V0(_) => panic!("Expected V1 Version"),
            HealthCheckVersion::V1(state) => state,
        };

        assert!(matches!(dp_state, DataPlaneState::Error(_)));
    }

    #[tokio::test]
    async fn test_enclave_health_check_service_with_draining_set_to_true() {
        // the data-plane status should error, as its not running
        IS_DRAINING.set(true).unwrap();
        let response = run_ecs_health_check_service(true, ControlPlaneState::Ok, &test_identity())
            .await
            .unwrap();
        assert_eq!(response.status(), 500);
        println!("deep response: {response:?}");
        let health_check_log = response_to_health_check_log(response).await;

        assert_eq!(health_check_log.enclave, test_identity());

        let dp_state = match health_check_log.data_plane {
            HealthCheckVersion::V0(_) => panic!("Expected V1 Version"),
            HealthCheckVersion::V1(state) => state,
        };

        assert!(matches!(dp_state, DataPlaneState::Unknown(_)));
        assert!(matches!(
            health_check_log.control_plane,
            ControlPlaneState::Draining
        ));
    }
}
