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

#[derive(Serialize, Deserialize, Debug)]
pub enum ControlPlaneState {
    Draining,
    Ok,
}

impl HealthCheck for ControlPlaneState {
    fn status_code(&self) -> u16 {
        match self {
            ControlPlaneState::Ok => 200,
            ControlPlaneState::Draining => 500,
        }
    }
}

impl HealthCheck for DataPlaneState {
    fn status_code(&self) -> u16 {
        match self {
            DataPlaneState::Initialized(diagnostic) if diagnostic.is_healthy => 200,
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
    Unknown(String),
    Provisioning,
    Attesting,
    SourcingTlsCerts,
    Initialized(DataPlaneDiagnostic),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataPlaneDiagnostic {
    pub is_healthy: bool,
    pub user_process: Option<UserProcessHealth>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UserProcessHealth {
    Error(String),
    Response {
        status_code: u16,
        body: Option<serde_json::Value>,
    },
    Unknown(String),
}

impl UserProcessHealth {
    pub fn rank(&self) -> u8 {
        match self {
            UserProcessHealth::Error(_) => 1,
            UserProcessHealth::Unknown(_) => 2,
            UserProcessHealth::Response { .. } => 3,
        }
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
