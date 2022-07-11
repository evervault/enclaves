use std::fmt;
use thiserror::Error;

#[derive(Error)]
pub enum Error {
    Crypto(String),
    Network(#[from] crate::server::error::ServerError),
    IO(#[from] std::io::Error),
    #[cfg(feature = "network_egress")]
    DNS(#[from] crate::dns::error::DNSError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::Crypto(message) => message.clone(),
                Error::Network(server_error) => server_error.to_string(),
                Error::IO(message) => message.to_string(),
                #[cfg(feature = "network_egress")]
                Error::DNS(message) => message.to_string(),
            }
        )
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
