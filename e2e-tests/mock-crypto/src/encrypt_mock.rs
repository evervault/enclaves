use std::fmt::Display;

struct EncryptedValue(serde_json::Value);

impl Display for EncryptedValue {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "ev:{}:{}:$", get_string_repr_for_serde_value(&self.0), convert_value_to_string(&self.0))
  }
}

impl std::convert::Into<serde_json::Value> for EncryptedValue {
  fn into(self) -> serde_json::Value {
    self.0
  }
}

impl std::convert::TryFrom<String> for EncryptedValue {
  type Error = serde_json::Error;

  fn try_from(val: String) -> Result<Self, Self::Error> {
    if !val.starts_with("ev:") || !val.ends_with(":$") {
      panic!("bad cipher received");
    }
    let parsed_val = serde_json::from_str(val.split(":").nth(2).unwrap())?;
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

pub fn decrypt(value: String) -> Result<serde_json::Value, serde_json::Error> {
  let enc_val = EncryptedValue::try_from(value)?;
  Ok(enc_val.0)
}

pub fn convert_value_to_string(value: &serde_json::Value) -> String {
  value.as_str()
    .map(|val| val.to_string())
    .unwrap_or_else(|| serde_json::to_string(&value).unwrap())
}