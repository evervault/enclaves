pub const ENCLAVE_CERT_PORT: u16 = 7775;
pub const ENCLAVE_CONFIG_PORT: u16 = 7776;
pub const ENCLAVE_CONNECT_PORT: u16 = 7777;
pub const ENCLAVE_CRYPTO_PORT: u16 = 7778;
pub const ENCLAVE_HEALTH_CHECK_PORT: u16 = 7779;
pub const EGRESS_PROXY_VSOCK_PORT: u16 = 4433;
pub const EGRESS_PROXY_PORT: u16 = 4444;
pub const DNS_PROXY_VSOCK_PORT: u16 = 8585;
pub const STATS_VSOCK_PORT: u16 = 8129;
pub const ENCLAVE_ACME_PORT: u16 = 7780;
#[cfg(not(feature = "enclave"))]
pub const ENCLAVE_STATSD_PORT: u16 = 8122;
#[cfg(feature = "enclave")]
pub const ENCLAVE_STATSD_PORT: u16 = 8125;
#[cfg(feature = "enclave")]
pub const ENCLAVE_CID: u32 = 2021;
#[cfg(feature = "enclave")]
pub const PARENT_CID: u32 = 3;
#[cfg(not(feature = "enclave"))]
pub const ENCLAVE_IP: &str = "172.20.0.7";
#[cfg(not(feature = "enclave"))]
pub const PARENT_IP: &str = "172.20.0.8";

pub mod acme;
pub mod logging;
pub mod rpc;
pub mod server;
pub mod stats;
pub mod utils;

lazy_static::lazy_static! {
  pub static ref CLIENT_VERSION: String = option_env!("CARGO_PKG_VERSION").map(|version| version.to_string()).unwrap_or_else(|| "unknown".to_string());
  pub static ref CLIENT_MAJOR_VERSION: String = option_env!("CARGO_PKG_VERSION").and_then(|version| version.split('.').next().map(|major| major.to_string())).unwrap_or_else(|| "unknown".to_string());
}
