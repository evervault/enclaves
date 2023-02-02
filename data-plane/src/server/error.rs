#[cfg(feature = "enclave")]
use crate::crypto::attest::AttestationError;
use crate::CageContextError;
use rcgen::RcgenError;
use std::fmt::Formatter;
use thiserror::Error;
use tokio_rustls::rustls::sign::SignError;

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
    OpensslError(#[from] openssl::error::ErrorStack),
    SignError(#[from] SignError),
    PemError(#[from] pem::PemError),
    CertProvisionerError(String),
    CageContextError(#[from] CageContextError),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub type ServerResult<T> = Result<T, TlsError>;
