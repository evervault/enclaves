use crate::dns::error::DNSError::RpcError;
use std::fmt;
use thiserror::Error;

#[derive(Error)]
pub enum DNSError {
    IO(#[from] std::io::Error),
    DNSEncodeError(#[from] dns_message_parser::EncodeError),
    DNSDecodeError(#[from] dns_message_parser::DecodeError),
    RpcError(#[from] shared::rpc::error::RpcError),
    MissingIP(String),
}

impl fmt::Display for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DNSError::DNSDecodeError(message) => message.to_string(),
                DNSError::DNSEncodeError(message) => message.to_string(),
                DNSError::IO(message) => message.to_string(),
                RpcError(message) => message.to_string(),
                DNSError::MissingIP(message) => message.to_string(),
            }
        )
    }
}

impl fmt::Debug for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
