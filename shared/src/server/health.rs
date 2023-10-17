use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug)]
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
