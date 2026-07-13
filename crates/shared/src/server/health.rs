use serde::{Deserialize, Serialize};

/// This is for representing healthcheck verions across the control-plane <-> data-plane http
/// boundary. It's not tied to v0/v1 enclaves release. There are many v1 enclaves that will
/// report v0 healthchecks until they are updated.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HealthCheckVersion {
    V0(HealthCheckLog),
    V1(DataPlaneState),
}

impl HealthCheckVersion {
    pub fn status_code(&self) -> u16 {
        match self {
            HealthCheckVersion::V0(log) => log.status_code(),
            HealthCheckVersion::V1(dp_state) => dp_state.status_code(),
        }
    }
}

impl From<DataPlaneState> for HealthCheckVersion {
    fn from(state: DataPlaneState) -> Self {
        HealthCheckVersion::V1(state)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCheckLog {
    pub status: HealthCheckStatus,
    pub message: Option<String>,
}

impl HealthCheckLog {
    pub fn new(status: HealthCheckStatus, message: Option<String>) -> HealthCheckLog {
        HealthCheckLog { status, message }
    }

    pub fn status_code(&self) -> u16 {
        self.status.status_code()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum HealthCheckStatus {
    Ignored,
    Ok,
    Unknown,
    Err,
    Uninitialized,
}

impl HealthCheckStatus {
    pub fn status_code(&self) -> u16 {
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
            Uninitialized => write!(f, "Uninitialized"),
        }
    }
}

pub trait HealthCheck {
    fn status_code(&self) -> u16;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlPlaneState {
    Draining,
    Ok,
    Error(String),
}

impl HealthCheck for ControlPlaneState {
    fn status_code(&self) -> u16 {
        match self {
            ControlPlaneState::Ok => 200,
            ControlPlaneState::Draining => 500,
            ControlPlaneState::Error(_) => 500,
        }
    }
}

impl HealthCheck for DataPlaneState {
    fn status_code(&self) -> u16 {
        match self {
            DataPlaneState::Initialized(diagnostic) if diagnostic.is_healthy() => 200,
            DataPlaneState::Provisioning
            | DataPlaneState::Attesting
            | DataPlaneState::SourcingTlsCerts => 200,
            _ => 500,
        }
    }
}

impl HealthCheck for HealthCheckLog {
    fn status_code(&self) -> u16 {
        self.status_code()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataPlaneState {
    Error(String),
    Unknown(String),
    Provisioning,
    Attesting,
    SourcingTlsCerts,
    Initialized(DataPlaneDiagnostic),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataPlaneDiagnostic {
    pub user_process: UserProcessHealth,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EnclaveIdentity {
    pub app_uuid: String,
    pub team_uuid: String,
    pub enclave_uuid: String,
    pub name: String,
}

impl DataPlaneDiagnostic {
    pub fn is_healthy(&self) -> bool {
        match self.user_process {
            UserProcessHealth::Unknown(_) => true,
            UserProcessHealth::Error(_) => false,
            UserProcessHealth::Response { status_code, .. } => (200..300).contains(&status_code),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UserProcessHealth {
    Unknown(String),
    Error(String),
    Response {
        status_code: u16,
        body: Option<serde_json::Value>,
    },
}

impl UserProcessHealth {
    pub fn rank(&self) -> u8 {
        match self {
            UserProcessHealth::Unknown(_) => 0,
            UserProcessHealth::Error(_) => 2,
            UserProcessHealth::Response { status_code, .. } => {
                if *status_code >= 200 && *status_code < 300 {
                    1
                } else {
                    3
                }
            }
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

impl Ord for UserProcessHealth {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for UserProcessHealth {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn booting_states_report_healthy_status_code() {
        assert_eq!(DataPlaneState::Provisioning.status_code(), 200);
        assert_eq!(DataPlaneState::Attesting.status_code(), 200);
        assert_eq!(DataPlaneState::SourcingTlsCerts.status_code(), 200);
    }

    #[test]
    fn error_and_unknown_states_report_unhealthy_status_code() {
        assert_eq!(DataPlaneState::Error("boom".into()).status_code(), 500);
        assert_eq!(DataPlaneState::Unknown("unknown".into()).status_code(), 500);
    }

    #[test]
    fn provisioning_state_serializes_to_stable_wire_format() {
        // The control plane parses this JSON off the DP<->CP boundary, so the shape matters.
        let provisioning = serde_json::to_string(&DataPlaneState::Provisioning).unwrap();
        assert_eq!(provisioning, "\"Provisioning\"");

        let initialized =
            serde_json::to_string(&DataPlaneState::Initialized(DataPlaneDiagnostic {
                user_process: UserProcessHealth::Response {
                    status_code: 200,
                    body: None,
                },
            }))
            .unwrap();
        // The data plane reports only user-process health here; enclave identity is added
        // by the control plane on its own envelope, not carried in this payload.
        assert_eq!(
            initialized,
            r#"{"Initialized":{"user_process":{"Response":{"status_code":200,"body":null}}}}"#
        );

        // And it round-trips back through the same deserializer the control plane uses.
        let decoded: DataPlaneState = serde_json::from_str("\"Provisioning\"").unwrap();
        assert!(matches!(decoded, DataPlaneState::Provisioning));
    }

    #[test]
    fn enclave_identity_serializes_to_stable_wire_format() {
        // The control plane emits this on its healthcheck envelope, so the shape matters.
        let identity = serde_json::to_string(&EnclaveIdentity {
            app_uuid: "app_123".into(),
            team_uuid: "team_456".into(),
            enclave_uuid: "enclave_789".into(),
            name: "my-enclave".into(),
        })
        .unwrap();
        assert_eq!(
            identity,
            r#"{"app_uuid":"app_123","team_uuid":"team_456","enclave_uuid":"enclave_789","name":"my-enclave"}"#
        );
    }

    #[tokio::test]
    async fn it_returns_errors_over_healthy_up_responses() {
        let max = [
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Response {
                status_code: 200,
                body: None,
            },
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(max, UserProcessHealth::Error(_)));
    }

    #[tokio::test]
    async fn it_returns_errors_over_unknown() {
        let max = [
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(max, UserProcessHealth::Error(_)));
    }

    #[tokio::test]
    async fn it_returns_unhealthy_up_responses_over_errors() {
        let max = [
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Response {
                status_code: 500,
                body: None,
            },
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(
            max,
            UserProcessHealth::Response {
                status_code: 500,
                body: None,
            }
        ));
    }
}
