use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HealthCheckVersion {
    V0(HealthCheckLog),
    V1(HealthCheckLog),
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

pub type DataPlaneHealthCheck = Result<DataPlaneState, String>;

impl HealthCheck for DataPlaneHealthCheck {
    fn status_code(&self) -> u16 {
        match self {
            Ok(state) => match state {
                DataPlaneState::Initialized(diagnostic) if diagnostic.is_healthy => 200,
                _ => 500,
            },
            _ => 500,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DataPlaneState {
    Unknown(String),
    Provisioning,
    Attesting,
    SourcingTlsCerts,
    Initialized(DataPlaneDiagnostic),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataPlaneDiagnostic {
    pub is_healthy: bool,
    pub customer_process: CustomerProcessHealth,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomerProcessHealth {
    pub status_code: u16,
    pub response: Option<serde_json::Value>,
}
