pub const ENCLAVE_CONNECT_PORT: u16 = 7777;
pub const ENCLAVE_CRYPTO_PORT: u16 = 8888;
#[cfg(feature = "enclave")]
pub const ENCLAVE_CID: u32 = 2021;

pub mod client;
pub mod rpc;
pub mod server;
pub mod utils;
