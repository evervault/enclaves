use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("IO Error — {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("Hyper Error — {0:?}")]
    HyperError(#[from] hyper::Error),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Request to server failed with status: {0:?}")]
    FailedRequest(hyper::StatusCode),
    #[error("Client Error — {0}")]
    ClientError(String),
    #[error("HTTP Error — {0:?}")]
    HttpError(#[from] hyper::http::Error),
    #[error("No Nonce Found")]
    NoNonce,
    #[error("Http Header Conversion Error")]
    HeaderConversionError(#[from] hyper::header::ToStrError),
    #[error("ACME Error {0:?}")]
    General(String),
}
