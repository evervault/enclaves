use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rpc(#[from] shared::rpc::error::RpcError),
    #[error(transparent)]
    Server(#[from] shared::server::error::ServerError),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    HyperHttp(#[from] hyper::http::Error),
    #[error(transparent)]
    DNSError(#[from] ResolveError),
    #[error("Request to internal IP ({0}) blocked")]
    IllegalInternalIp(std::net::Ipv4Addr),
    #[error("Invalid IP included in egress request — {0}")]
    InvalidIp(#[from] std::net::AddrParseError),
    #[error("Failed sending request - {0}")]
    FailedRequest(String),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ServerError>;
