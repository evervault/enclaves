use aws_nitro_enclaves_cose as cose;
use aws_nitro_enclaves_nsm_api as nitro;
use chrono::{TimeZone, Utc};
use openssl::x509::X509;
use serde_bytes::ByteBuf;
use std::fmt::Formatter;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum DriverCalls {
    GetAttestationDocument,
    GetRandom,
}

impl std::fmt::Display for DriverCalls {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::GetAttestationDocument => "get_attestation_document",
                Self::GetRandom => "get_random",
            }
        )
    }
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("An error occurred while requesting the attestation document - {0:?}")]
    AttestationFailed(nitro::api::ErrorCode),
    #[error("Received an unexpected response when calling {0} — {1:?}")]
    UnexpectedResponse(DriverCalls, nitro::api::Response),
    #[error("Could not parse CoseSign1 structure: {0}")]
    CoseSign1ParseFailed(serde_cbor::Error),
    #[error("Could not parse attestation document: {0}")]
    AttestationDocParseFailed(serde_cbor::Error),
    #[error("Could not parse signing cert: {0}")]
    SigningCertParseFailed(openssl::error::ErrorStack),
}

pub fn get_attestation_doc(public_key_hash: Option<Vec<u8>>) -> Result<Vec<u8>, AttestationError> {
    let nsm_fd: i32 = nitro::driver::nsm_init();
    let nonce = match nitro::driver::nsm_process_request(nsm_fd, nitro::api::Request::GetRandom) {
        nitro::api::Response::GetRandom {
            random: random_bytes,
        } => random_bytes,
        unexpected_response => {
            return Err(AttestationError::UnexpectedResponse(
                DriverCalls::GetRandom,
                unexpected_response,
            ))
        }
    };

    let nsm_request = nitro::api::Request::Attestation {
        user_data: public_key_hash.map(ByteBuf::from),
        nonce: Some(ByteBuf::from(nonce)),
        public_key: None,
    };

    match nitro::driver::nsm_process_request(nsm_fd, nsm_request) {
        nitro::api::Response::Attestation { document } => Ok(document),
        nitro::api::Response::Error(err) => Err(AttestationError::AttestationFailed(err)),
        unexpected_response => Err(AttestationError::UnexpectedResponse(
            DriverCalls::GetAttestationDocument,
            unexpected_response,
        )),
    }
}

pub fn get_expiry_time(cose_sign_1_bytes: &[u8]) -> Result<SystemTime, AttestationError> {
    let cose_sign_1: cose::CoseSign1 = serde_cbor::from_slice(cose_sign_1_bytes)
        .map_err(|e| AttestationError::CoseSign1ParseFailed(e))?;
    // Can only return an error if verification fails, and we aren't doing verification
    let attestation_doc_bytes = cose_sign_1
        .get_payload::<cose::crypto::Openssl>(None)
        .unwrap();
    let attestation_doc: nitro::api::AttestationDoc =
        serde_cbor::from_slice(&attestation_doc_bytes)
            .map_err(|e| AttestationError::AttestationDocParseFailed(e))?;
    let signing_cert = X509::from_der(&attestation_doc.certificate[..])
        .map_err(|e| AttestationError::SigningCertParseFailed(e))?;
    let chrono_expiry_time = Utc
        .datetime_from_str(
            &signing_cert.not_after().to_string(),
            "%b %e %H:%M:%S %Y %Z",
        )
        .expect("OpenSSL breaking change!");
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(chrono_expiry_time.timestamp() as u64))
}
