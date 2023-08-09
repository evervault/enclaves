use crate::acme::error::*;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;

pub fn b64(data: &[u8]) -> String {
    base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>, AcmeError> {
    base64::decode_config(data, ::base64::URL_SAFE_NO_PAD).map_err(AcmeError::Base64DecodeError)
}

/// Generate a new P256 EC private key using the system random.
pub fn gen_ec_private_key() -> Result<PKey<Private>, AcmeError> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("Infallible - Harcoded NID");
    let rsa = EcKey::generate(&group)?;
    let key = PKey::from_ec_key(rsa)?;
    Ok(key)
}
