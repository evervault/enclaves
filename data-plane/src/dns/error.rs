use shared::server::{egress::EgressError, error::ServerError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DNSError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("DNS query format error — no questions found")]
    DNSNoQuestionsFound,
    #[error("{0}")]
    RpcError(#[from] shared::rpc::error::RpcError),
    #[error("{0}")]
    MissingIP(String),
    #[error("{0}")]
    TlsParseError(String),
    #[error("Could not find a hostname in the TLS hello message. Perhaps SNI is not being used.")]
    NoHostnameFound,
    #[error("Egress error {0}")]
    EgressError(#[from] EgressError),
    #[error("DNS lookup failed due to a timeout after: {0}")]
    DNSTimeout(#[from] tokio::time::error::Elapsed),
    #[error("An error occurred while connecting to the host process - {0}")]
    BridgeNetworkingError(#[from] ServerError),
}
