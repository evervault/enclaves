use std::{
    fs::{File, OpenOptions},
    io::Write,
};

#[cfg(not(feature = "tls_termination"))]
use crate::cert_provisioner_client::CertProvisionerClient;
#[cfg(not(feature = "tls_termination"))]
use crate::config_client::ConfigClient;
use crate::{base_tls_client::ClientError, CageContextError};
use hyper::header::InvalidHeaderValue;
use serde_json::json;
use shared::server::config_server::requests::Secret;
use thiserror::Error;

use crate::e3client::{CryptoRequest, CryptoResponse, E3Client};

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
    #[error("Couldn't get cage context")]
    CageContextError(#[from] CageContextError),
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
    pub async fn init_without_certs(self) -> Result<(), EnvError> {
        use crate::CageContext;

        println!("Initializing env without TLS termination, sending request to control plane for cert provisioner token.");
        let token = self.config_client.get_cert_token().await.unwrap().token();
        let cert_response = self.cert_provisioner_client.get_secrets(token).await?;
        CageContext::set(cert_response.clone().context.into());

        self.init(cert_response.clone().secrets).await?;
        Ok(())
    }

    fn write_env_file(self, secrets: Vec<Secret>) -> Result<(), EnvError> {
        let mut file = File::create("/etc/customer-env")?;

        let env_string = secrets
            .iter()
            .filter(|env| env.name != "EV_CAGE_INITIALIZED")
            .map(|env| format!("export {}={}  ", env.name, env.secret))
            .collect::<Vec<String>>()
            .join("");

        file.write_all(env_string.as_bytes())?;
        Ok(())
    }

    pub fn write_startup_complete_env_vars() -> Result<(), EnvError> {
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open("/etc/customer-env")?;

        write!(file, "export EV_CAGE_INITIALIZED=true  ")?;
        write!(file, "export EV_API_KEY=placeholder  ")?;

        Ok(())
    }
}
