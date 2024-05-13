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
    write!(f, "ev:{}:{}:{}:{}:$", get_string_repr_for_serde_value(&self.0), mock_iv(), mock_pub_key(), encoded_val)
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
    let decoded_val = base64::decode(val.split(":").nth(4).unwrap()).map_err(|_| MockCryptoError::InvalidCipher)?;
    let decoded_str = std::str::from_utf8(&decoded_val).map_err(|_| MockCryptoError::InvalidCipher)?;
    let parsed_val = serde_json::from_str(decoded_str)?;
    Ok(Self(parsed_val))
  }
}

fn get_string_repr_for_serde_value(val: &serde_json::Value) -> String {
  match val {
    serde_json::Value::String(_) => "string".to_string(),
    serde_json::Value::Number(_) => "number".to_string(),
    serde_json::Value::Bool(_) => "boolean".to_string(),
    serde_json::Value::Null => "null".to_string(),
    _ => unimplemented!("Ciphertexts can only represent primitives")
  }
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
  let mut iv = [0u8;16];
  rand::thread_rng().fill_bytes(&mut iv);
  base64::encode(iv)
}

fn mock_pub_key() -> String {
  let mut pub_key = [0u8;44];
  rand::thread_rng().fill_bytes(&mut pub_key);
  base64::encode(pub_key)
}