use shared::server::error::ServerError;
use thiserror::Error;

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
}

pub type Result<T> = std::result::Result<T, Error>;
