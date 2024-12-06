#[cfg(feature = "enclave")]
use crate::crypto::attest::AttestationError;
use crate::ContextError;
use std::{num::TryFromIntError, time::SystemTimeError};
use thiserror::Error;
use tokio_rustls::rustls::sign::SignError;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("IoError - {0}")]
    IoError(#[from] std::io::Error),
    #[error("TlsError - {0}")]
    TlsError(#[from] tokio_rustls::rustls::Error),
    #[error("NoHostnameSpecified - Invalid config options given to generate certificate")]
    NoHostnameSpecified,
    #[error("NoCertFound - Failed to load TLS certificate for the Enclave")]
    NoCertFound,
    #[error("NoKeyFound - Failed to load the private key for the Enclave")]
    NoKeyFound,
    #[error(transparent)]
    ServerError(#[from] shared::server::error::ServerError),
    #[cfg(feature = "enclave")]
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    #[error("OpensslError")]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("SignError")]
    SignError(#[from] SignError),
    #[error("PemError")]
    PemError(#[from] pem::PemError),
    #[error("CertProvisionerError - {0}")]
    CertProvisionerError(String),
    #[error("ContextError - Failed to access Enclave context: {0}")]
    ContextError(#[from] ContextError),
    #[error("SystemTimeError - {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("TryFromIntError - {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("EnvError - an unexpected error occurred while preparing the Enclave environment")]
    EnvError(#[from] crate::env::EnvError),
}

pub type ServerResult<T> = Result<T, TlsError>;
