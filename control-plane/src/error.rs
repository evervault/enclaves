use std::fmt::Formatter;
use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

#[derive(Error, Debug)]
pub enum ServerError {
    Io(#[from] std::io::Error),
    Rpc(#[from] shared::rpc::error::RpcError),
    Server(#[from] shared::server::error::ServerError),
    Hyper(#[from] hyper::http::Error),
    DNSError(#[from] ResolveError),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type Result<T> = std::result::Result<T, ServerError>;
