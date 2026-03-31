use thiserror::Error;
extern crate rmp_serde as rmps;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("An error occured while decoding the message - {0:?}")]
    DecodeError(#[from] rmps::decode::Error),
    #[error("An error occured while encoding the message - {0:?}")]
    EncodeError(#[from] rmps::encode::Error),
}
