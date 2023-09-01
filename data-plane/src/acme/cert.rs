use std::{str::from_utf8, sync::Arc, time::Duration};

use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_rustls::rustls::{
    sign::{self, CertifiedKey},
    Certificate, PrivateKey, ServerName,
};

use crate::{
    config_client::{ConfigClient, StorageConfigClientInterface},
    configuration,
    e3client::{CryptoRequest, CryptoResponse, E3Client},
    CageContext,
};

use super::{
    account::{Account, AccountBuilder},
    client::AcmeClient,
    directory::Directory,
    error::AcmeError,
    lock::StorageLock,
    order::OrderBuilder,
};

const CERTIFICATE_LOCK_NAME: &str = "certificate";
const CERTIFICATE_OBJECT_KEY: &str = "certificate.pem";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawAcmeCertificate {
    pub certificate: String,
}

impl RawAcmeCertificate {
    pub fn new(certificate: String) -> Self {
        Self { certificate }
    }

    pub fn from_x509s(x509s: Vec<X509>) -> Result<RawAcmeCertificate, AcmeError> {
        let pem_string = Self::convert_to_pemfile(x509s)?;

        Ok(RawAcmeCertificate::new(pem_string))
    }

    fn convert_to_pemfile(certificates: Vec<X509>) -> Result<String, AcmeError> {
        let mut pem_strings: Vec<String> = Vec::new();

        for x509 in certificates {
            let pem = x509.to_pem()?;
            let pem_string = from_utf8(&pem)?.to_string();
            pem_strings.push(pem_string);
        }

        let combined_pem: String = pem_strings.join("\n");

        Ok(combined_pem)
    }

    pub async fn from_storage(
        config_client: ConfigClient,
    ) -> Result<Option<RawAcmeCertificate>, AcmeError> {
        let response_maybe = config_client
            .get_object(CERTIFICATE_OBJECT_KEY.into())
            .await?;

        let parsed_response =
            response_maybe.map(|response| RawAcmeCertificate::new(response.body()));

        Ok(parsed_response)
    }

    fn to_certified_key(&self, private_key: PKey<Private>) -> Result<CertifiedKey, AcmeError> {
        let der_encoded_private_key = private_key.private_key_to_der()?;
        let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key))?;

        let certs = X509::stack_from_pem(&self.certificate.as_bytes())?;

        let mut pem_certs = Vec::new();
        for cert in certs.iter() {
            let pem_encoded_cert: Vec<u8> = cert.to_pem()?;
            pem_certs.push(pem_encoded_cert);
        }

        let combined_pem_encoded_certs: Vec<u8> = pem_certs.concat();
        let parsed_pems = pem::parse_many(combined_pem_encoded_certs)?;
        let cert_chain: Vec<Certificate> = parsed_pems
            .into_iter()
            .map(|p| Certificate(p.contents))
            .collect();
        let cert_and_key = CertifiedKey::new(cert_chain, ecdsa_private_key);
        Ok(cert_and_key)
    }

    pub async fn persist(&self, config_client: &ConfigClient) -> Result<(), AcmeError> {
        config_client
            .put_object(CERTIFICATE_OBJECT_KEY.into(), self.certificate.clone())
            .await?;

        Ok(())
    }
}

pub struct AcmeCertificateRetreiver {
    pub config_client: ConfigClient,
    pub e3_client: E3Client,
    pub acme_account: Option<Arc<Account<AcmeClient>>>,
}

impl AcmeCertificateRetreiver {
    pub fn new(config_client: ConfigClient, e3_client: E3Client) -> Self {
        Self {
            config_client,
            e3_client,
            acme_account: None,
        }
    }

    pub async fn get_or_create_cage_certificate(
        &mut self,
        key: PKey<Private>,
        cage_context: CageContext,
    ) -> Result<CertifiedKey, AcmeError> {
        println!("[ACME] Starting polling for ACME certificate");
        let mut persisted_certificate: Option<CertifiedKey> = None;

        let max_checks = 10;
        let mut i = 0;

        while persisted_certificate.is_none() {
            i += 1;

            if i >= max_checks {
                return Err(AcmeError::General(
                    "Max retries for getting certificate reached".into(),
                ));
            }

            if let Some(decrypted_certificate) =
                self.fetch_and_decrypt_certificate(key.clone()).await?
            {
                persisted_certificate = Some(decrypted_certificate);
            } else {
                println!("[ACME] Certificate not found in storage, checking for lock");
                if Self::order_lock_exists_and_is_valid().await? {
                    println!("[ACME] Lock is valid, waiting for Certificate to be created by other instance or waiting for lock to expire");
                    //Do nothing if Lock is not expired - wait for certificate to be created by other instance or wait for lock to expire
                } else {
                    println!(
                        "[ACME] No valid lock on ACME ordering, creating lock and certificate."
                    );
                    //No Lock on order - create lock - create Certificate - encrypt Certificate - persist Certificate - delete lock
                    let decrypted_certificate_maybe = self
                        .create_certificate_and_persist_with_lock(key.clone(), &cage_context)
                        .await?;
                    persisted_certificate = decrypted_certificate_maybe;
                }
            };

            if persisted_certificate.is_none() {
                println!("[ACME] Certificate not found, sleeping for 5 seconds");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }

        if let Some(persisted_certificate) = persisted_certificate {
            println!("[ACME] Certificate found after polling");
            Ok(persisted_certificate)
        } else {
            Err(AcmeError::General(
                "[ACME] Certificate not found after polling".into(),
            ))
        }
    }

    async fn fetch_and_decrypt_certificate(
        &self,
        key: PKey<Private>,
    ) -> Result<Option<CertifiedKey>, AcmeError> {
        if let Some(raw_acme_certificate) =
            RawAcmeCertificate::from_storage(self.config_client.clone()).await?
        {
            println!("[ACME] Certificate found in storage");
            //Certificate already exists, decrypt it
            let decrypted_certificate =
                Self::decrypt_certificate(&self.e3_client, &raw_acme_certificate).await?;
            Some(decrypted_certificate.to_certified_key(key)).transpose()
        } else {
            println!("[ACME] Certificate not found in storage");
            Ok(None)
        }
    }

    async fn order_lock_exists_and_is_valid() -> Result<bool, AcmeError> {
        let order_lock_maybe = StorageLock::read_from_storage(CERTIFICATE_LOCK_NAME.into()).await?;
        match order_lock_maybe {
            Some(lock) => Ok(!lock.is_expired()),
            None => Ok(false),
        }
    }

    async fn create_certificate_and_persist_with_lock(
        &mut self,
        key: PKey<Private>,
        cage_context: &CageContext,
    ) -> Result<Option<CertifiedKey>, AcmeError> {
        let certificate_lock = StorageLock::new_with_config_client(
            CERTIFICATE_LOCK_NAME.into(),
            self.config_client.clone(),
        );
        if certificate_lock.write_and_check_persisted().await? {
            let cert_domain = cage_context.get_trusted_cert_name();
            let raw_acme_certificate = self.order_certificate(cert_domain, key.clone()).await?;

            let encrypted_raw_certificate =
                Self::encrypt_certificate(&self.e3_client, &raw_acme_certificate).await?;

            encrypted_raw_certificate
                .persist(&self.config_client)
                .await?;

            certificate_lock.delete().await?;

            Ok(Some(raw_acme_certificate.to_certified_key(key)?))
        } else {
            Ok(None)
        }
    }

    async fn init_acme_account(&self) -> Result<Arc<Account<AcmeClient>>, AcmeError> {
        let server_name = ServerName::try_from(configuration::get_acme_host().as_str())
            .expect("Hardcoded hostname");
        let acme_client = AcmeClient::new(server_name);
        let path = configuration::get_acme_base_path();

        let directory =
            Directory::fetch_directory(path, acme_client, self.config_client.clone()).await?;

        let acme_account = AccountBuilder::new(directory)
            .contact(vec![String::from("mailto:engineering@evervault.com")])
            .terms_of_service_agreed(true)
            .build()
            .await?;

        Ok(acme_account)
    }

    //Use all the acme libraries to order cert
    async fn order_certificate(
        &mut self,
        domain: String,
        key: PKey<Private>,
    ) -> Result<RawAcmeCertificate, AcmeError> {
        if self.acme_account.is_none() {
            self.acme_account = Some(self.init_acme_account().await?);
        };

        let acme_account = match self.acme_account {
            Some(ref acme_account) => acme_account.clone(),
            None => {
                let new_account = self.init_acme_account().await?;
                self.acme_account = Some(new_account.clone());
                new_account
            }
        };

        let mut order_builder = OrderBuilder::new(acme_account);

        order_builder.add_dns_identifier(domain);

        let order = order_builder.build().await?;
        let authorizations = order.authorizations().await?;

        for auth in authorizations {
            let challenge = auth
                .get_challenge("http-01")
                .ok_or(AcmeError::FieldNotFound(
                    "Challenge not found in authorization".into(),
                ))?;

            let token = challenge.clone().token.ok_or(AcmeError::FieldNotFound(
                "Token not found in challenge returned".into(),
            ))?;

            let path = format!("acme-challenges/{}", token);

            let token_value =
                challenge
                    .key_authorization()
                    .await?
                    .ok_or(AcmeError::FieldNotFound(
                        "Token not found in challenge returned".into(),
                    ))?;

            self.config_client
                .put_object(path.clone(), token_value)
                .await?;

            let challenge_validated = challenge.validate().await?;

            challenge_validated
                .wait_done(Duration::from_secs(5), 5)
                .await?;

            auth.wait_done(Duration::from_secs(5), 5).await?;
        }

        let order_ready = order.wait_ready(Duration::from_secs(5), 5).await?;
        let order_finalized = order_ready.finalize(key).await?;

        let order_complete = order_finalized
            .wait_done(Duration::from_secs(5), 5)
            .await
            .unwrap();

        let cert_chain = order_complete
            .certificate()
            .await?
            .ok_or(AcmeError::FieldNotFound(
                "Certificate not found in completed order".into(),
            ))?;

        let raw = RawAcmeCertificate::from_x509s(cert_chain);
        println!("Raw certificate: {:?}", raw);
        raw
    }

    async fn decrypt_certificate(
        e3_client: &E3Client,
        encrypted_raw_acme_certificate: &RawAcmeCertificate,
    ) -> Result<RawAcmeCertificate, AcmeError> {
        let e3_response: CryptoResponse = e3_client
            .decrypt(CryptoRequest {
                data: json!(encrypted_raw_acme_certificate),
            })
            .await?;

        let decrypted_acme_key_pair: RawAcmeCertificate = serde_json::from_value(e3_response.data)?;

        Ok(decrypted_acme_key_pair)
    }

    async fn encrypt_certificate(
        e3_client: &E3Client,
        raw_acme_certificate: &RawAcmeCertificate,
    ) -> Result<RawAcmeCertificate, AcmeError> {
        let e3_response: CryptoResponse = e3_client
            .encrypt(CryptoRequest {
                data: json!(raw_acme_certificate),
            })
            .await?;

        let encrypted_acme_key_pair: RawAcmeCertificate = serde_json::from_value(e3_response.data)?;

        Ok(encrypted_acme_key_pair)
    }
}
