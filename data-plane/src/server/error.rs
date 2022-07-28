#[cfg(feature = "enclave")]
use crate::crypto::attest::AttestationError;
use rcgen::RcgenError;
use std::fmt::Formatter;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    IoError(#[from] std::io::Error),
    TlsError(#[from] tokio_rustls::rustls::Error),
    NoCertFound,
    NoKeyFound,
    ServerError(#[from] shared::server::error::ServerError),
    #[cfg(feature = "enclave")]
    Attestation(#[from] AttestationError),
    CertGenError(#[from] RcgenError),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type ServerResult<T> = Result<T, TlsError>;
