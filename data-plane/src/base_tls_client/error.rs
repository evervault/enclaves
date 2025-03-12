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
    #[error("Failed to open connection: {0}")]
    ServerError(#[from] shared::server::error::ServerError),
    #[error("Client Error {0:?}")]
    General(String),
}
