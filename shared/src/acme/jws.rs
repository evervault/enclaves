use crate::acme::error::*;
use crate::acme::helpers::*;
use crate::server::config_server::requests::{JwkResponse, JwsResponse};
use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::Id;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::sign::Signer;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct JwsHeader {
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    url: String,
}

fn extract_ec_coordinates(
    key: &EcKey<openssl::pkey::Private>,
) -> Result<(String, String), AcmeError> {
    let group = key.group();
    let public_key = key.public_key();
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    let mut ctx = BigNumContext::new()?;

    public_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    let x_coord = b64(&x.to_vec());
    let y_coord: String = b64(&y.to_vec());
    Ok((x_coord, y_coord))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl From<&Jwk> for JwkThumb {
    fn from(jwk: &Jwk) -> Self {
        JwkThumb {
            crv: jwk.crv.clone(),
            kty: jwk.kty.clone(),
            x: jwk.x.clone(),
            y: jwk.y.clone(),
        }
    }
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

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Jwk {
    alg: String,
    crv: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    x: String,
    y: String,
}

impl Jwk {
    pub fn new(pkey: &PKey<Private>) -> Result<Jwk, AcmeError> {
        let ec_key = pkey.ec_key()?;

        let (x, y) = extract_ec_coordinates(&ec_key)?;
        Ok(Jwk {
            alg: "ES256".to_string(),
            crv: "P-256".to_string(),
            kty: "EC".to_string(),
            _use: "sig".to_string(),
            x,
            y,
        })
    }

    pub fn to_response(&self) -> JwkResponse {
        let jwk = self.to_owned();
        JwkResponse {
            alg: jwk.alg,
            crv: jwk.crv,
            kty: jwk.kty,
            _use: jwk._use,
            x: jwk.x,
            y: jwk.y,
        }
    }
}

pub struct JoseJson {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

impl JoseJson {
    pub fn new(protected: String, payload: String, signature: String) -> Self {
        Self {
            protected,
            payload,
            signature,
        }
    }
}

impl JoseJson {}

#[derive(Serialize, Debug, Clone)]
pub struct JwsResult {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

impl From<&JwsResult> for JwsResponse {
    fn from(jws: &JwsResult) -> Self {
        JwsResponse {
            protected: jws.protected.clone(),
            payload: jws.payload.clone(),
            signature: jws.signature.clone(),
        }
    }
}

pub fn jws(
    url: &str,
    nonce: Option<String>,
    payload: &str,
    pkey: Option<PKey<Private>>,
    account_id: Option<String>,
) -> Result<JwsResult, AcmeError> {
    let payload_b64 = b64(payload.as_bytes());

    let alg: String = match &pkey {
        Some(key) if key.id() == Id::HMAC => "HS256".into(),
        _ => "ES256".into(),
    };

    let mut header = JwsHeader {
        nonce,
        alg: alg.clone(),
        url: url.to_string(),
        ..Default::default()
    };

    if let Some(kid) = account_id {
        header.kid = kid.into();
    } else if let Some(pkey) = &pkey {
        let jwk = Jwk::new(pkey)?;
        header.jwk = Some(jwk);
    }

    let protected_b64 = b64(&serde_json::to_string(&header)?.into_bytes());
    let signature_b64 = {
        let private_key = match pkey {
            Some(key) => key,
            None => return Err(AcmeError::PrivateKeyNotSet),
        };

        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
        signer.update(&format!("{}.{}", protected_b64, payload_b64).into_bytes())?;
        let der_encoded_sig = signer.sign_to_vec()?;

        if alg == "HS256" {
            b64(&der_encoded_sig)
        } else {
            der_sig_to_jws_sig(&der_encoded_sig)?
        }
    };

    Ok(JwsResult {
        protected: protected_b64,
        payload: payload_b64,
        signature: signature_b64,
    })
}

fn der_sig_to_jws_sig(der_encoded_sig: &[u8]) -> Result<String, AcmeError> {
    let ecdsa_sig = EcdsaSig::from_der(der_encoded_sig)?;
    let r = ecdsa_sig.r();
    let s = ecdsa_sig.s();

    let mut r_arr = [0u8; 32];
    let mut s_arr = [0u8; 32];
    let r_vec = r.to_vec();
    let s_vec = s.to_vec();

    let r_offset = 32 - r_vec.len();
    r_arr[r_offset..].copy_from_slice(&r_vec[..]);

    let s_offset = 32 - s_vec.len();
    s_arr[s_offset..].copy_from_slice(&s_vec[..]);

    let mut raw_sig = Vec::new();
    raw_sig.extend_from_slice(&r_arr);
    raw_sig.extend_from_slice(&s_arr);

    Ok(b64(&raw_sig))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub r#type: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::helpers;

    #[test]
    fn test_valid_signed_jws() {
        let ec = helpers::gen_ec_private_key().unwrap();

        let jws = jws(
            "https://example.com/acme/new-order",
            None,
            "{}",
            Some(ec.clone()),
            None,
        );

        assert!(jws.is_ok());

        // Verify the signature using the public key
        let jws = jws.unwrap();
        let signature_bytes = b64_decode(&jws.signature).unwrap();

        // Assuming `signature_bytes` is the raw signature in the JWS format
        let r = BigNum::from_slice(&signature_bytes[..32]).unwrap();
        let s = BigNum::from_slice(&signature_bytes[32..]).unwrap();
        let ecdsa_sig = EcdsaSig::from_private_components(r, s).unwrap();

        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &ec).unwrap();
        verifier
            .update(&format!("{}.{}", jws.protected, jws.payload).into_bytes())
            .unwrap();

        // Perform the verification
        assert!(verifier.verify(&ecdsa_sig.to_der().unwrap()).unwrap());
    }

    #[test]
    fn test_invalid_signed_jws() {
        let ec = helpers::gen_ec_private_key().unwrap();

        let jws = jws(
            "https://example.com/acme/new-order",
            None,
            "{}",
            Some(ec.clone()),
            None,
        );

        let jws = jws.unwrap();
        let signature_bytes = b64_decode(&jws.signature).unwrap();

        // Assuming `signature_bytes` is the raw signature in the JWS format
        let r = BigNum::from_slice(&signature_bytes[..32]).unwrap();
        let s = BigNum::from_slice(&signature_bytes[32..]).unwrap();
        let ecdsa_sig = EcdsaSig::from_private_components(r, s).unwrap();

        let verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &ec).unwrap();

        let valid = verifier.verify(&ecdsa_sig.to_der().unwrap()).unwrap();
        assert!(valid == false);
    }
}
