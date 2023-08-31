use openssl::pkey::PKey;
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::{config_client::ConfigClient, e3client::E3Client, CageContext};

use self::{cert::AcmeCertificateRetreiver, error::AcmeError, key::AcmeKeyRetreiver};

pub mod account;
pub mod authorization;
pub mod cert;
pub mod client;
pub mod directory;
pub mod error;
pub mod key;
pub mod lock;
pub mod order;

#[cfg(test)]
pub mod mocks;

pub async fn get_trusted_cert() -> Result<CertifiedKey, AcmeError> {
    let config_client = ConfigClient::new();
    let e3_client = E3Client::new();
    let cage_context = CageContext::get()?;

    let trusted_key_pair: PKey<openssl::pkey::Private> =
        AcmeKeyRetreiver::new(config_client.clone(), e3_client.clone())
            .get_or_create_cage_key_pair()
            .await
            .expect("Failed to get key pair for trusted cert");

    AcmeCertificateRetreiver::new(config_client, e3_client)
        .get_or_create_cage_certificate(trusted_key_pair, cage_context)
        .await
}
