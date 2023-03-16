pub const ENCLAVE_CERT_PORT: u16 = 7775;
pub const ENCLAVE_CONFIG_PORT: u16 = 7776;
pub const ENCLAVE_CONNECT_PORT: u16 = 7777;
pub const ENCLAVE_CRYPTO_PORT: u16 = 7778;
pub const ENCLAVE_HEALTH_CHECK_PORT: u16 = 7779;
pub const EGRESS_PROXY_VSOCK_PORT: u16 = 4433;
pub const DNS_PROXY_VSOCK_PORT: u16 = 8585;
pub const STATS_VSOCK_PORT: u16 = 8129;
#[cfg(not(feature = "enclave"))]
pub const ENCLAVE_STATSD_PORT: u16 = 8122;
#[cfg(feature = "enclave")]
pub const ENCLAVE_STATSD_PORT: u16 = 8125;
#[cfg(feature = "enclave")]
pub const ENCLAVE_CID: u32 = 2021;
#[cfg(feature = "enclave")]
pub const PARENT_CID: u32 = 3;

pub mod logging;
pub mod rpc;
pub mod server;
pub mod utils;
