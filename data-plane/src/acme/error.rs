use std::string::FromUtf8Error;

use serde::Deserialize;
use thiserror::Error;

use crate::{
    base_tls_client::BaseClientError, config_client::ConfigClientError, crypto::e3client::E3Error,
    CageContextError,
};

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error(transparent)]
    ClientError(#[from] BaseClientError),
    #[error("HTTP Error — {0:?}")]
    HttpError(#[from] hyper::http::Error),
    #[error("No Nonce Found")]
    NoNonce,
    #[error("Nonce Mutex Poison Error")]
    NoncePoisonError,
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
    #[error(transparent)]
    E3Error(#[from] E3Error),
    #[error("Chrono DataTime Parse Error - {0:?}")]
    ParseError(#[from] chrono::ParseError),
    #[error("PEM Error - {0:?}")]
    PEMError(#[from] pem::PemError),
    #[error("Rustls Error - {0:?}")]
    RustlsSignError(#[from] tokio_rustls::rustls::sign::SignError),
    #[error("Cage Context Error - {0:?}")]
    CageContextError(#[from] CageContextError),
    #[error("ACME Error {0:?}")]
    AcmeError(#[from] shared::acme::error::AcmeError),
    #[error(transparent)]
    ConfigClient(#[from] ConfigClientError),
    #[error("Max retries ({limit}) reached while requesting {target_resource}")]
    MaxRetriesReached {
        limit: usize,
        target_resource: String,
    },
    #[error("No private key found for ACME account")]
    NoPrivateKey,
    #[error("No location header set on new order response")]
    MissingLocationHeader,
    #[error("Failed to resolve {0} after polling")]
    ResourceNotFound(String),
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
