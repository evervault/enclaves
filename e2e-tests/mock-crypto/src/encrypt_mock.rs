use std::fmt::Display;
use thiserror::Error;
use rand::RngCore;

#[derive(Debug,Error)]
pub enum MockCryptoError {
  #[error(transparent)]
  SerdeError(#[from] serde_json::Error),
  #[error("Invalid cipher received")]
  InvalidCipher
}

struct EncryptedValue(serde_json::Value);

impl Display for EncryptedValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let val_str = convert_value_to_string(&self.0);
    let encoded_val = base64::encode(&val_str);
    match get_string_repr_for_serde_value(&self.0) {
      Some(val) => write!(f, "ev:{}:{}:{}:{}:$", val, mock_iv(), mock_pub_key(), encoded_val),
      None => write!(f, "ev:{}:{}:{}:$", mock_iv(), mock_pub_key(), encoded_val),
    }
  }
}

impl std::convert::Into<serde_json::Value> for EncryptedValue {
  fn into(self) -> serde_json::Value {
    self.0
  }
}

impl std::convert::TryFrom<String> for EncryptedValue {
  type Error = MockCryptoError;

  fn try_from(val: String) -> Result<Self, Self::Error> {
    if !val.starts_with("ev:") || !val.ends_with(":$") {
      return Err(MockCryptoError::InvalidCipher);
    }
    // Use second last token as value
    let mut tokens = val.split(":").collect::<Vec<_>>().into_iter();
    let decoded_val = base64::decode(tokens.nth_back(1).unwrap()).map_err(|_| MockCryptoError::InvalidCipher)?;
    let decoded_str = std::str::from_utf8(&decoded_val).map_err(|_| MockCryptoError::InvalidCipher)?;
    let parsed_val = serde_json::from_str(decoded_str)?;
    Ok(Self(parsed_val))
  }
}

fn get_string_repr_for_serde_value(val: &serde_json::Value) -> Option<String> {
  let repr = match val {
    serde_json::Value::String(_) => {
      return None;
    },
    serde_json::Value::Number(_) => "number".to_string(),
    serde_json::Value::Bool(_) => "boolean".to_string(),
    _ => unimplemented!("Ciphertexts can only represent primitives")
  };
  Some(repr)
}

pub fn encrypt(value: serde_json::Value) -> serde_json::Value {
  serde_json::Value::String(format!("{}", EncryptedValue(value)))
}

pub fn decrypt(value: String) -> Result<serde_json::Value, MockCryptoError> {
  let enc_val = EncryptedValue::try_from(value)?;
  Ok(enc_val.0)
}

pub fn convert_value_to_string(value: &serde_json::Value) -> String {
  value.as_str()
    .map(|val| val.to_string())
    .unwrap_or_else(|| serde_json::to_string(&value).unwrap())
}

fn mock_iv() -> String {
  let mut iv = [0u8;12];
  rand::thread_rng().fill_bytes(&mut iv);
  base64::encode(iv)
}

fn mock_pub_key() -> String {
  let mut pub_key = [0u8;33];
  rand::thread_rng().fill_bytes(&mut pub_key);
  base64::encode(pub_key)
}