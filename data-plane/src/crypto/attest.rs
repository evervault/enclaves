use aws_nitro_enclaves_nsm_api as nitro;
use serde_bytes::ByteBuf;
use std::fmt::Formatter;
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
