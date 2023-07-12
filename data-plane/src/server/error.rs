#[cfg(feature = "enclave")]
use crate::crypto::attest::AttestationError;
use crate::CageContextError;
use std::{fmt::Formatter, num::TryFromIntError, time::SystemTimeError};
use thiserror::Error;
use tokio_rustls::rustls::sign::SignError;

#[derive(Error, Debug)]
pub enum TlsError {
    IoError(#[from] std::io::Error),
    TlsError(#[from] tokio_rustls::rustls::Error),
    NoHostnameSpecified,
    NoCertFound,
    NoKeyFound,
    ServerError(#[from] shared::server::error::ServerError),
    #[cfg(feature = "enclave")]
    Attestation(#[from] AttestationError),
    OpensslError(#[from] openssl::error::ErrorStack),
    SignError(#[from] SignError),
    PemError(#[from] pem::PemError),
    CertProvisionerError(String),
    CageContextError(#[from] CageContextError),
    SystemTimeError(#[from] SystemTimeError),
    TryFromIntError(#[from] TryFromIntError),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub type ServerResult<T> = Result<T, TlsError>;
