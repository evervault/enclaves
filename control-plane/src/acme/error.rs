use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("HTTP Error — {0:?}")]
    HttpError(#[from] hyper::http::Error),
    #[error("OpenSSL Error — {0:?}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("Base64 Decode Error — {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("ACME Error {0:?}")]
    General(String),
}
