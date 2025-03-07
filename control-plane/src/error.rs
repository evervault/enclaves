use shared::server::sni::SNIError;
use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

use storage_client_interface::StorageClientError;

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
    IllegalInternalIp(std::net::IpAddr),
    #[error("Invalid IP included in egress request — {0}")]
    InvalidIp(#[from] std::net::AddrParseError),
    #[error("Failed sending request - {0}")]
    FailedRequest(String),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("Error Setting up Mtls for Cert Provisioner: {0}")]
    CertProvisionerMtls(String),
    #[error(transparent)]
    EnvError(#[from] std::env::VarError),
    #[cfg(feature = "network_egress")]
    #[error("Egress error: {0}")]
    EgressError(#[from] shared::server::egress::EgressError),
    #[error("Storage Error - {0}")]
    StorageClientError(#[from] StorageClientError),
    #[error("Acme Error - {0}")]
    AcmeError(#[from] shared::acme::error::AcmeError),
    #[error("Invalid DNS Config provided - at least 2 valid DNS Servers must be provided")]
    InvalidDnsConfig,
    #[error(transparent)]
    SNIError(#[from] SNIError),
}

pub type Result<T> = std::result::Result<T, ServerError>;
