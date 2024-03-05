use axum::{routing::post, Router};
use axum::{extract, Json};
use axum_server::tls_rustls::RustlsConfig;
use rustls::server::ServerConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::Infallible;
use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::http::HeaderMap;

lazy_static::lazy_static! {
  static ref APP_UUID: String = std::env::var("EV_APP_UUID").expect("No app id given");
  static ref API_KEY: String = std::env::var("EV_API_KEY").expect("No api key given");
}

#[tokio::main]
async fn main() {
  tokio::join!(
    run_https_server(7676),
    run_http_server(7677),
  );
}

async fn run_https_server(port: u16) {
  let tls_key = std::env::var("MOCK_CRYPTO_KEY").expect("No key given");
  let tls_cert = std::env::var("MOCK_CRYPTO_CERT").expect("No cert given");

  let key_bytes = tls_key.as_bytes().to_vec();
  let cert_bytes = tls_cert.as_bytes().to_vec();

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
    .route("/authenticate", post(authentication_handler))
}

fn encrypt(value: &mut Value) {
  if value.is_object() {
    value.as_object_mut().unwrap().values_mut().for_each(encrypt);
  } else if value.is_array() {
    value.as_array_mut().unwrap().iter_mut().for_each(encrypt);
  } else {
    let to_encrypt = serde_json::Value::String(convert_value_to_string(&value));
    let client = reqwest::blocking::Client::new();
    let response = client.post("https://api.evervault.com/encrypt")
      .basic_auth(&*APP_UUID,Some(&*API_KEY))
      .json(&to_encrypt)
      .send()
      .unwrap();
    *value = Value::String(response.text().unwrap());
  }
}

fn decrypt(value: &mut Value) {
  if value.is_object() {
    value.as_object_mut().unwrap().values_mut().for_each(decrypt);
  } else if value.is_array() {
    value.as_array_mut().unwrap().iter_mut().for_each(decrypt);
  } else if value.is_string() { // all encrypted values are strings
    let to_decrypt = serde_json::Value::String(convert_value_to_string(&value)); // convert from serde value string to std string
    let client = reqwest::blocking::Client::new();
    let response = client.post("https://api.evervault.com/decrypt")
      .basic_auth(&*APP_UUID,Some(&*API_KEY))
      .json(&to_decrypt)
      .send()
      .unwrap();
    if let Ok(decrypted) = response.text() {
      *value = serde_json::Value::String(decrypted);
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

async fn authentication_handler(headers: HeaderMap) -> impl IntoResponse {
  match headers.get("api-key") {
    Some(key) => {
      if key.to_str().unwrap() == "e0hrSRE7NYXmyoG7aAlRbu/Vgly7ak/4dkqCnB044+VH+xuJkMwiIGt2C4xBQ82um7AwsOX/rvytn4Hlb6izsw==" {
        println!("[Mock Crypto API] - Recieved request to authenticate!");
        StatusCode::OK
      } else {
        println!("[Mock Crypto API] - Invalid API key recieved");
        StatusCode::UNAUTHORIZED
      }
    },
    None => return StatusCode::UNAUTHORIZED
  }
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestPayload {
  data: Value
}

impl RequestPayload {
  fn data_mut(&mut self) -> &mut Value {
    &mut self.data
  }
}
