use std::{env, fs::File, io::Write};

#[cfg(not(feature = "tls_termination"))]
use crate::cert_provisioner_client::CertProvisionerClient;
#[cfg(not(feature = "tls_termination"))]
use crate::config_client::ConfigClient;
use crate::{base_tls_client::ClientError, CageContext, CageContextError};
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
    #[error("No api key was provided in the env")]
    MissingApiKey,
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
        let api_key = secrets
            .iter()
            .find(|secret| secret.name == "EV_API_KEY")
            .ok_or(EnvError::MissingApiKey)?;
        env::set_var(api_key.clone().name, api_key.clone().secret);

        let (encrypted_env, plaintext_env): (_, Vec<Secret>) = secrets
            .clone()
            .into_iter()
            .partition(|env| env.secret.starts_with("ev:"));

        let mut plaintext_env = plaintext_env;

        let cage_context = CageContext::get()?;

        if !encrypted_env.is_empty() {
            let e3_response: CryptoResponse = self
                .e3_client
                .decrypt(CryptoRequest {
                    app_uuid: cage_context.app_uuid.clone(),
                    team_uuid: cage_context.team_uuid.clone(),
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
        use shared::server::config_server::routes::ConfigServerPath;

        println!("Initializing env without TLS termination, sending request to control plane for cert provisioner token.");
        let token = self.config_client.get_cert_token().await.unwrap().token();
        let cert_response = self.cert_provisioner_client.get_secrets(token).await?;
        CageContext::set(cert_response.clone().context.into());

        self.init(cert_response.clone().secrets).await?;
        Ok(())
    }

    fn write_env_file(self, secrets: Vec<Secret>) -> Result<(), EnvError> {
        let mut file = File::create("/etc/customer-env")?;
        let mut env_string: String = "".to_owned();

        secrets.iter().for_each(|env| {
            let value = &format!("export {}={}  ", env.name, env.secret);
            env_string.push_str(value)
        });
        file.write_all(env_string.as_bytes())?;
        Ok(())
    }
}
