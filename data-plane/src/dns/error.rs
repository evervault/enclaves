use shared::server::egress::EgressError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DNSError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    DNSEncodeError(#[from] dns_message_parser::EncodeError),
    #[error("{0}")]
    DNSDecodeError(#[from] dns_message_parser::DecodeError),
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
}
