use serde::Deserialize;
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
    #[error("Nonce Mutex Poison Error - {0:?}")]
    PoisonError(String),
    #[error("Http Header Conversion Error")]
    HeaderConversionError(#[from] hyper::header::ToStrError),
    #[error("OpenSSL Error — {0:?}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("Base64 Decode Error — {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("Error interpretting utf8 sequence — {0:?}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("No directory for acme account - {0:?}")]
    NoDirectory(String),
    #[error("Error creating CSR - {0:?}")]
    CsrError(String),
    #[error("{0:?} Field Not Found")]
    FieldNotFound(String),
    #[error("ACME Error {0:?}")]
    General(String),
}

/// This is an error as returned by the ACME server.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeServerError {
    pub r#type: Option<String>,
    pub title: Option<String>,
    pub status: Option<u16>,
    pub detail: Option<String>,
}
