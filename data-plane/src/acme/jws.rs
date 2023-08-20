use serde::Deserialize;
use serde::Serialize;
use shared::server::config_server::requests::JwkResponse;
use shared::server::config_server::requests::JwsResponse;

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl From<&JwkResponse> for JwkThumb {
    fn from(jwk: &JwkResponse) -> Self {
        JwkThumb {
            crv: jwk.crv.clone(),
            kty: jwk.kty.clone(),
            x: jwk.x.clone(),
            y: jwk.y.clone(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct JwsResult {
    protected: String,
    payload: String,
    signature: String,
}

impl From<&JwsResponse> for JwsResult {
    fn from(jws: &JwsResponse) -> Self {
        Self {
            protected: jws.protected.clone(),
            payload: jws.payload.clone(),
            signature: jws.signature.clone(),
        }
    }
}

#[cfg(test)]
mod tests {}
