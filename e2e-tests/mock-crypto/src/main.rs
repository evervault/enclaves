use axum::{routing::post, Router};
use axum::{extract, Json};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::ServerConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::Infallible;
use std::fs;
use rust_crypto::backend::{CryptoClient, Datatype};

lazy_static::lazy_static! {
  static ref KEY_PAIR: rust_crypto::backend::ies_secp256r1_openssl::Client = create_key_pair();
}

#[tokio::main]
async fn main() {
  tokio::join!(
    run_https_server(7676),
    run_http_server(7677),
  );
}

fn create_key_pair() -> rust_crypto::backend::ies_secp256r1_openssl::Client {
  let keypair = rust_crypto::backend::ies_secp256r1_openssl::EcKey::generate_key_pair().unwrap();
  rust_crypto::backend::ies_secp256r1_openssl::Client::new(keypair)
}

async fn run_https_server(port: u16) {
  let tls_key = std::env::var("MOCK_CRYPTO_KEY").expect("No key given");
  let tls_cert = std::env::var("MOCK_CRYPTO_CERT").expect("No cert given");

  let in_ci = std::env::var("CI").map(|ci_flag| ci_flag == "true").unwrap_or_else(|_| false);
  let key_bytes = if in_ci { tls_key.as_bytes().to_vec() } else { fs::read(&tls_key).expect("Failed to read key") };
  let cert_bytes = if in_ci { tls_cert.as_bytes().to_vec() } else { fs::read(&tls_cert).expect("Failed to read cert") };

  let cert_chain: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut cert_bytes.as_ref())
    .map(|certs| 
      certs.into_iter().map(rustls::Certificate).collect()
    )
    .expect("Failed to parse cert");

  let keys = rustls_pemfile::pkcs8_private_keys(&mut key_bytes.as_ref()).expect("Failed to parse pk");

  let tls_cfg = ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(cert_chain, rustls::PrivateKey(keys.get(0).unwrap().clone()))
    .expect("Failed to build server");
  let tls_cfg = std::sync::Arc::new(tls_cfg);

  let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
  let router = get_router();
  println!("Starting https mock e3 on {port}");
  axum_server::bind_rustls(addr, RustlsConfig::from_config(tls_cfg))
      .serve(router.into_make_service())
      .await
      .expect("Could not bind https server");
}

async fn run_http_server(port: u16) {
  let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
  let router = get_router();
  println!("Starting http mock e3 on {port}");
  axum::Server::bind(&addr)
      .serve(router.into_make_service())
      .await
      .expect("Could not bind http server");
}

fn get_router() -> Router {
  Router::new()
    .route("/encrypt", post(encryption_handler))
    .route("/decrypt", post(decryption_handler))
    .route("/attestation-doc", post(attestation_handler))
}

fn encrypt(value: &mut Value) {
  if value.is_object() {
    value.as_object_mut().unwrap().values_mut().for_each(encrypt);
  } else if value.is_array() {
    value.as_array_mut().unwrap().iter_mut().for_each(encrypt);
  } else {
    let mut val = value.clone();
    let to_encrypt = convert_value_to_string(&value);
    let encrypted_data_result = KEY_PAIR.encrypt(
      to_encrypt, 
      Datatype::try_from(&mut val).unwrap(), 
      false
    ).unwrap();
    *value = Value::String(encrypted_data_result);
  }
}

fn decrypt(value: &mut Value) {
  if value.is_object() {
    value.as_object_mut().unwrap().values_mut().for_each(decrypt);
  } else if value.is_array() {
    value.as_array_mut().unwrap().iter_mut().for_each(decrypt);
  } else if value.is_string() { // all encrypted values are strings
    let to_decrypt = convert_value_to_string(&value); // convert from serde value string to std string
    if let Ok(decrypted) = KEY_PAIR.decrypt(to_decrypt) {
      *value = decrypted;
    }
  }
}

fn convert_value_to_string(value: &Value) -> String {
  value.as_str()
    .map(|val| val.to_string())
    .unwrap_or_else(|| serde_json::to_string(&value).unwrap())
}

async fn encryption_handler(
  extract::Json(mut request_payload): extract::Json<RequestPayload>
) -> Result<Json<RequestPayload>, Infallible> {
  println!("[Mock Crypto API] - Recieved request to encrypt!");
  encrypt(request_payload.data_mut());
  Ok(Json(request_payload))
}

async fn decryption_handler(
  extract::Json(mut request_payload): extract::Json<RequestPayload>
) -> Result<Json<RequestPayload>, Infallible> {
  println!("[Mock Crypto API] - Recieved request to decrypt!");
  decrypt(request_payload.data_mut());
  Ok(Json(request_payload))
}

async fn attestation_handler() -> Result<Vec<u8>, Infallible> {
  let pcr0 = std::env::var("PCR0").expect("No PCR0 given");
  let pcr1 = std::env::var("PCR1").expect("No PCR1 given");
  let pcr2 = std::env::var("PCR2").expect("No PCR2 given");
  let pcr8 = std::env::var("PCR8").expect("No PCR8 given");
  let ad = serde_json::json!({
    "Measurements": { 
      "PCR0": pcr0, 
      "PCR1": pcr1, 
      "PCR2": pcr2,
      "PCR8": pcr8
    }
  });
  Ok(serde_cbor::to_vec(&ad).unwrap())
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestPayload {
  app_uuid: String,
  team_uuid: String,
  data: Value
}

impl RequestPayload {
  fn data_mut(&mut self) -> &mut Value {
    &mut self.data
  }
}
