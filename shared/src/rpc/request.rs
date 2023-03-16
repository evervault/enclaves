extern crate rmp_serde as rmps;
extern crate serde;
extern crate serde_derive;
use crate::rpc::error::RpcError;

use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize, Eq)]
pub struct ExternalRequest {
    pub ip: String,
    pub data: Vec<u8>,
    pub port: u16,
}

impl ExternalRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, RpcError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<ExternalRequest, RpcError> {
        let mut deserializer = Deserializer::new(&bytes[..]);
        let res = Deserialize::deserialize(&mut deserializer)?;
        Ok(res)
    }
}
