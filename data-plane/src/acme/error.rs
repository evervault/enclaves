use std::string::FromUtf8Error;

use serde::Deserialize;
use thiserror::Error;

use crate::{base_tls_client::ClientError, error, ContextError};

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
    #[error("Error interpretting utf8 sequence — {0:?}")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("No directory for acme account - {0:?}")]
    NoDirectory(String),
    #[error("Error creating CSR - {0:?}")]
    CsrError(String),
    #[error("{0:?} Field Not Found")]
    FieldNotFound(String),
    #[error("Config Client Error {0:?}")]
    ConfigClient(#[from] error::Error),
    #[error("E3 Client Error {0:?}")]
    E3ClientError(#[from] ClientError),
    #[error("Chrono DataTime Parse Error - {0:?}")]
    ParseError(#[from] chrono::ParseError),
    #[error("PEM Error - {0:?}")]
    PEMError(#[from] pem::PemError),
    #[error("Rustls Error - {0:?}")]
    RustlsSignError(#[from] tokio_rustls::rustls::sign::SignError),
    #[error("Failed to access context - {0}")]
    ContextError(#[from] ContextError),
    #[error("System Time Error - {0:?}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("ACME Error {0:?}")]
    AcmeError(#[from] shared::acme::error::AcmeError),
    #[error("Error creating connection to host: {0}")]
    ServerError(#[from] shared::server::error::ServerError),
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
