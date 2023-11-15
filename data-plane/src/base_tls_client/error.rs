use std::string::FromUtf8Error;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("IO Error — {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("Hyper Error — {0:?}")]
    HyperError(#[from] hyper::Error),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Request to server failed with status: {0:?}")]
    FailedRequest(hyper::StatusCode),
    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("Client Error {0:?}")]
    General(String),
}
