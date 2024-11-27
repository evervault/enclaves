#[cfg(not(feature = "tls_termination"))]
use crate::cert_provisioner_client::CertProvisionerClient;
#[cfg(not(feature = "tls_termination"))]
use crate::config_client::ConfigClient;
use crate::{base_tls_client::ClientError, ContextError};
use hyper::header::InvalidHeaderValue;
use serde_json::json;
use shared::server::config_server::requests::Secret;
#[cfg(not(feature = "tls_termination"))]
use std::future::Future;
use std::{
    fs::{File, OpenOptions},
    io::Write,
};
use thiserror::Error;

use crate::e3client::{CryptoRequest, CryptoResponse, E3Api, E3Client};

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Client error — {0}")]
    ClientError(#[from] ClientError),
    #[error("Could not create header value — {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("Failed to read context - {0}")]
    ContextError(#[from] ContextError),
}

#[derive(Clone)]
pub struct Environment {
    #[cfg(not(feature = "tls_termination"))]
    pub cert_provisioner_client: CertProvisionerClient,
    #[cfg(not(feature = "tls_termination"))]
    pub config_client: ConfigClient,
    pub e3_client: E3Client,
}

impl Environment {
    #[cfg(not(feature = "tls_termination"))]
    pub fn new() -> Environment {
        let cert_provisioner_client = CertProvisionerClient::new();
        let e3_client = E3Client::new();
        let config_client = ConfigClient::new();
        Environment {
            cert_provisioner_client,
            e3_client,
            config_client,
        }
    }

    pub async fn init(self, secrets: Vec<Secret>) -> Result<(), EnvError> {
        let (encrypted_env, plaintext_env): (_, Vec<Secret>) = secrets
            .clone()
            .into_iter()
            .partition(|env| env.secret.starts_with("ev:"));

        let mut plaintext_env = plaintext_env;

        if !encrypted_env.is_empty() {
            let e3_response: CryptoResponse = self
                .e3_client
                .decrypt(CryptoRequest {
                    data: json!(encrypted_env.clone()),
                })
                .await?;
            let mut decrypted_env: Vec<Secret> = serde_json::from_value(e3_response.data)?;
            decrypted_env.append(&mut plaintext_env);
            self.write_env_file(decrypted_env.clone())?;
        } else {
            self.write_env_file(plaintext_env.clone())?;
        }

        Ok(())
    }

    #[cfg(not(feature = "tls_termination"))]
    async fn with_retries<F, Fut, T>(backoff: u32, n_attempts: u8, upper_bound: u32, func: F) -> Result<T, crate::error::Error>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, crate::error::Error>>,
    {
        use rand::thread_rng;

        let mut attempts = 0;
        loop {
            let computed_backoff = (2.pow(attempts) * backoff) + thread_rng().gen_range(50..150);
            attempts += 1;
            match func().await {
                Ok(response) => return Ok(response),
                Err(e) if attempts < n_attempts => {
                    log::error!("Request failed during environment init flow - {e:?}");
                    let limited_backoff = std::cmp::min(upper_bound, computed_backoff);
                    tokio::time::sleep(tokio::time::Duration::from_millis(limited_backoff)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(not(feature = "tls_termination"))]
    pub async fn init_without_certs(self) -> crate::error::Result<()> {
        use crate::EnclaveContext;

        let half_min = 1_000 * 30;
        log::info!("Initializing env without TLS termination, sending request to control plane for cert provisioner token.");
        let token = Self::with_retries(500, 10, half_min, || async {
            self.config_client
                .get_cert_token()
                .await
                .map_err(crate::error::Error::from)
        })
        .await?
        .token();

        let secrets_response = Self::with_retries(500, 10, half_min, || async {
            self.cert_provisioner_client
                .get_secrets(token.clone())
                .await
                .map_err(crate::error::Error::from)
        })
        .await?;

        EnclaveContext::set(secrets_response.context.clone().into());

        self.init(secrets_response.clone().secrets).await?;

        //Write vars to indicate enclave is initialised
        let _ = Self::write_startup_complete_env_vars();

        Ok(())
    }

    fn write_env_file(self, secrets: Vec<Secret>) -> Result<(), EnvError> {
        let mut file = File::create("/etc/customer-env")?;

        let env_string = secrets
            .iter()
            .map(|env| format!("export {}={}  ", env.name, env.secret))
            .collect::<Vec<String>>()
            .join("");

        file.write_all(env_string.as_bytes())?;
        Ok(())
    }

    pub fn write_startup_complete_env_vars() -> Result<(), EnvError> {
        let mut file = OpenOptions::new().append(true).open("/etc/customer-env")?;

        write!(file, "export EV_INITIALIZED=true")?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[tokio::test]
    #[cfg(not(feature = "tls_termination"))]
    async fn with_retries_redrives_requests_as_expected() {
        let responses = vec![
            Ok(()),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
        ];

        let ctr = std::sync::Arc::new(std::sync::Mutex::new(responses));
        let ctr_clone = ctr.clone();
        let fallable_func = || async {
            let mut ctr_lock = ctr.lock().unwrap();
            let value = (*ctr_lock).pop().unwrap();
            value
        };

        let result = super::Environment::with_retries(100, 3, 1_000, fallable_func).await;
        assert!(result.is_ok());
        let responses_lock = ctr_clone.lock().unwrap();
        assert!(responses_lock.is_empty());
    }

    #[tokio::test]
    #[cfg(not(feature = "tls_termination"))]
    async fn with_retries_redrives_requests_and_bubbles_errors() {
        let responses = vec![
            Ok(()),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
        ];

        let ctr = std::sync::Arc::new(std::sync::Mutex::new(responses));
        let ctr_clone = ctr.clone();
        let fallable_func = || async {
            let mut ctr_lock = ctr.lock().unwrap();
            let value = (*ctr_lock).pop().unwrap();
            value
        };

        let result = super::Environment::with_retries(100, 3, 1_000, fallable_func).await;
        assert!(result.is_err());
        let responses_lock = ctr_clone.lock().unwrap();
        assert_eq!(responses_lock.len(), 1);
    }
}
