use hyper::header::{InvalidHeaderName, InvalidHeaderValue};
use shared::server::error::ServerError;
use thiserror::Error;

use crate::{base_tls_client::ClientError, env::EnvError, CageContextError};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("No api-key header present on request")]
    NoApiKeyGiven,
    #[error("Invalid api key provided")]
    FailedToAuthenticateApiKey,
}

impl From<AuthError> for hyper::Response<hyper::Body> {
    fn from(err: AuthError) -> Self {
        let msg = err.to_string();
        hyper::Response::builder()
            .status(401)
            .body(msg.into())
            .expect("Failed to build auth error to response")
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Network(#[from] ServerError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "network_egress")]
    #[error("{0}")]
    DNS(#[from] crate::dns::error::DNSError),
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[cfg(feature = "tls_termination")]
    #[error("An error occurred while parsing the incoming stream for ciphertexts — {0}")]
    ParseError(#[from] crate::crypto::stream::IncomingStreamError),
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
    #[error("An error occurred — {0}")]
    ConfigServer(String),
    #[error("An error occurred requesting intermediate cert from the cert provisioner — {0}")]
    CertServer(String),
    #[error("Could not create header value — {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("Client error — {0}")]
    ClientError(#[from] ClientError),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Error initializing environment — {0:?}")]
    EnvError(#[from] EnvError),
    #[error("Couldn't get cage context")]
    CageContextError(#[from] CageContextError),
    #[cfg(feature = "enclave")]
    #[error("Failed to get connection to nsm")]
    NsmConnectionError(#[from] crate::utils::nsm::NsmConnectionError),
    #[error("Couldn't build header name")]
    InvalidHeaderName(#[from] InvalidHeaderName),
    #[error("Hyper error")]
    HyperError(#[from] hyper::http::Error),
    #[error("Api key is missing from request")]
    MissingApiKey,
    #[error("Api key is invalid")]
    ApiKeyInvalid,
}

pub type Result<T> = std::result::Result<T, Error>;
