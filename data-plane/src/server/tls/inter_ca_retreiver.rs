use std::fs::File;
use std::io::Write;

use hyper::http::HeaderValue;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde_json::json;
use shared::server::config_server::requests::Secret;

use crate::e3client::{CryptoRequest, CryptoResponse, E3Client};
use crate::{cert_provisioner_client, config_client, CageContext};
use crate::{cert_provisioner_client::CertProvisionerClient, config_client::ConfigClient};

use crate::error::{Error, Result};

pub struct InterCaRetreiver {
    cert_provisioner_client: CertProvisionerClient,
    config_client: ConfigClient,
    e3_client: E3Client,
    cage_context: CageContext,
}

impl InterCaRetreiver {
    pub fn new(cage_context: CageContext) -> Self {
        let cert_provisioner_client = cert_provisioner_client::CertProvisionerClient::new();
        let config_client = config_client::ConfigClient::new();
        let e3_client = E3Client::new();

        Self {
            cert_provisioner_client,
            config_client,
            e3_client,
            cage_context,
        }
    }

    pub async fn get_intermediate_ca(&self) -> Result<(X509, PKey<Private>)> {
        println!("Sending request to control plane for cert provisioner token.");
        let token = self.config_client.get_cert_token().await?.token();

        println!("Received token for cert provisioner. Requesting intermediate CA.");
        let cert_response = self
            .cert_provisioner_client
            .get_cert(token)
            .await
            .map_err(|err| Error::CertServer(err.to_string()))?;

        self.init_environment(cert_response.clone().secrets.unwrap())
            .await?;

        let inter_ca_cert = parse_cert(cert_response.cert())?;
        let inter_ca_key_pair = parse_key(cert_response.key_pair())?;

        Ok((inter_ca_cert, inter_ca_key_pair))
    }

    async fn init_environment(&self, secrets: Vec<Secret>) -> Result<()> {
        let api_key = secrets
            .iter()
            .find(|secret| secret.name == "EV_API_KEY")
            .ok_or(Error::MissingApiKey)?;
        let header = HeaderValue::from_str(&api_key.secret)?;

        let (encrypted_env, plaintext_env): (_, Vec<Secret>) = secrets
            .clone()
            .into_iter()
            .partition(|env| env.secret.starts_with("ev:"));

        let e3_response: CryptoResponse = self
            .e3_client
            .decrypt(
                &header,
                CryptoRequest {
                    app_uuid: self.cage_context.app_uuid.clone(),
                    team_uuid: self.cage_context.team_uuid.clone(),
                    data: json!(encrypted_env.clone()),
                },
            )
            .await?;

        let mut decrypted_env: Vec<Secret> = serde_json::from_value(e3_response.data).unwrap();

        let mut plaintext_env = plaintext_env;
        decrypted_env.append(&mut plaintext_env);

        Self::write_env_file(decrypted_env.clone())?;
        Ok(())
    }

    fn write_env_file(secrets: Vec<Secret>) -> Result<()> {
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

fn parse_cert(raw_cert: String) -> Result<X509> {
    let decoded_cert = base64::decode(raw_cert).map_err(|err| Error::Crypto(err.to_string()))?;
    X509::from_pem(&decoded_cert).map_err(|err| Error::Crypto(err.to_string()))
}

fn parse_key(raw_key: String) -> Result<PKey<Private>> {
    let decoded_key = base64::decode(raw_key).map_err(|err| Error::Crypto(err.to_string()))?;
    PKey::private_key_from_pem(&decoded_key).map_err(|err| Error::Crypto(err.to_string()))
}
