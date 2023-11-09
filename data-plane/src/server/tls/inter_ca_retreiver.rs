use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

use crate::crypto::e3client::E3Client;
use crate::env::Environment;
use crate::error::{Error, Result};
use crate::{cert_provisioner_client, config_client, CageContext};
use crate::{cert_provisioner_client::CertProvisionerClient, config_client::ConfigClient};

pub struct InterCaRetreiver {
    cert_provisioner_client: CertProvisionerClient,
    config_client: ConfigClient,
    env: Environment,
}

impl InterCaRetreiver {
    pub fn new() -> Self {
        let cert_provisioner_client = cert_provisioner_client::CertProvisionerClient::new();
        let config_client = config_client::ConfigClient::new();
        let e3_client = E3Client::new();
        let env = Environment { e3_client };

        Self {
            cert_provisioner_client,
            config_client,
            env,
        }
    }

    pub async fn get_intermediate_ca(&self) -> Result<(X509, PKey<Private>)> {
        log::info!("Sending request to control plane for cert provisioner token.");
        let token = self.config_client.get_cert_token().await?.token();

        log::info!("Received token for cert provisioner. Requesting intermediate CA.");
        let cert_response = self
            .cert_provisioner_client
            .get_cert(token)
            .await
            .map_err(|err| Error::CertServer(err.to_string()))?;
        CageContext::set(cert_response.context.clone().into());
        self.env
            .clone()
            .init(cert_response.clone().secrets.unwrap())
            .await?;

        let inter_ca_cert = parse_cert(cert_response.cert())?;
        let inter_ca_key_pair = parse_key(cert_response.key_pair())?;

        Ok((inter_ca_cert, inter_ca_key_pair))
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
