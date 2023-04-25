use std::fmt::Formatter;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    IoError(#[from] std::io::Error),
    Hyper(#[from] hyper::Error),
    JsonError(#[from] serde_json::Error),
    InvalidPath(String),
    #[cfg(feature = "network_egress")]
    EgressError(#[from] super::egress::EgressError),
    UnexpectedEOF,
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub type ServerResult<T> = std::result::Result<T, ServerError>;
