pub const ENCLAVE_CONNECT_PORT: u16 = 7777;
#[cfg(feature = "enclave")]
pub const ENCLAVE_CID: u32 = 2021;

pub mod rpc;
pub mod server;
pub mod utils;
