use std::{
    str::from_utf8,
    sync::Arc,
    time::{Duration, SystemTime},
};

use openssl::asn1::Asn1TimeRef;
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::X509,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_rustls::rustls::{
    sign::{self, CertifiedKey},
    Certificate, PrivateKey, ServerName,
};

use crate::{
    config_client::{ConfigClient, StorageConfigClientInterface},
    e3client::{CryptoRequest, CryptoResponse, E3Api, E3Client},
    server::tls::trusted_cert_container::TRUSTED_CERT_STORE,
    stats_client::StatsClient,
    EnclaveContext,
};

use super::{
    account::{Account, AccountBuilder},
    client::AcmeClient,
    directory::Directory,
    error::AcmeError,
    lock::StorageLock,
    order::OrderBuilder,
    provider::Provider,
};

const CERTIFICATE_LOCK_NAME: &str = "certificate-v1";
const CERTIFICATE_OBJECT_KEY: &str = "certificate-v1.pem";

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

    fn to_x509s(&self) -> Result<Vec<X509>, AcmeError> {
        let pem_encoded_certs = self.certificate.as_bytes();
        let certs = X509::stack_from_pem(pem_encoded_certs)?;
        Ok(certs)
    }

    pub fn time_till_renewal_required(&self, x509s: Vec<X509>) -> Result<Duration, AcmeError> {
        let thirty_days_from_now = Asn1Time::days_from_now(30)?;

        let mut earliest_expiry = None;
        for cert in x509s.iter() {
            let cert_expiry = cert.not_after();
            if earliest_expiry.is_none()
                || cert_expiry < earliest_expiry.expect("Infallible - Option checked")
            {
                earliest_expiry = Some(cert_expiry);
            }
        }

        if let Some(earliest_expiry) = earliest_expiry {
            // If the certificate expires in the next month, renew it immediately.
            if earliest_expiry < thirty_days_from_now {
                log::info!("[ACME] Certificate expires in the coming month. Renew it now now");
                return Ok(Duration::from_secs(0));
            }

            let thirty_days_in_seconds = 60 * 60 * 24 * 30;
            let time_till_expiry_converted = asn1_time_to_system_time(&earliest_expiry)?;
            let thirty_days_before_expiry =
                time_till_expiry_converted - Duration::from_secs(thirty_days_in_seconds);

            let time_to_renew_with_jitter = get_jittered_time(thirty_days_before_expiry);
            let time_till_renewal = time_to_renew_with_jitter.duration_since(SystemTime::now())?;
            return Ok(time_till_renewal);
        }

        //If failed to get expiry, renew straight away as cert must be corrupted
        Ok(Duration::from_secs(0))
    }

    fn to_certified_key(
        &self,
        x509s: Vec<X509>,
        private_key: PKey<Private>,
    ) -> Result<CertifiedKey, AcmeError> {
        let der_encoded_private_key = private_key.private_key_to_der()?;
        let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key))?;

        let mut pem_certs = Vec::new();
        for cert in x509s.iter() {
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

fn asn1_time_to_system_time(time: &Asn1TimeRef) -> Result<SystemTime, AcmeError> {
    let unix_time = Asn1Time::from_unix(0)?.diff(time)?;
    Ok(SystemTime::UNIX_EPOCH
        + Duration::from_secs(unix_time.days as u64 * 86400 + unix_time.secs as u64))
}

fn get_jittered_time(base_time: SystemTime) -> SystemTime {
    let mut rng = rand::thread_rng();
    let jitter_duration = Duration::from_secs(rng.gen_range(1..86400));
    base_time + jitter_duration
}

#[derive(Clone)]
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

    pub async fn get_or_create_enclave_certificate(
        &mut self,
        key: PKey<Private>,
        enclave_context: EnclaveContext,
    ) -> Result<CertifiedKey, AcmeError> {
        log::info!("[ACME] Starting polling for ACME certificate");
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

            if let Some(decrypted_certificate) = self
                .fetch_and_decrypt_certificate(key.clone(), &enclave_context)
                .await?
            {
                persisted_certificate = Some(decrypted_certificate);
            } else {
                log::info!("[ACME] Certificate not found in storage, checking for lock");
                let order_lock_maybe = Self::get_order_lock().await?;

                if Self::order_lock_exists_and_is_valid(&order_lock_maybe)? {
                    log::info!("[ACME] Lock is valid, waiting for Certificate to be created by other instance or waiting for lock to expire");
                    //Do nothing if Lock is not expired - wait for certificate to be created by other instance or wait for lock to expire
                } else {
                    let attempts = match order_lock_maybe {
                        Some(lock) => lock.number_of_attempts().unwrap_or(0),
                        None => 0,
                    };

                    log::info!(
                        "[ACME] No valid lock on ACME ordering, creating lock and certificate. {} attempt(s) made.",
                        attempts
                    );

                    //No Lock on order - create lock - create Certificate - encrypt Certificate - persist Certificate - delete lock
                    let decrypted_certificate_maybe = self
                        .create_certificate_and_persist_with_lock(
                            key.clone(),
                            &enclave_context,
                            attempts + 1,
                        )
                        .await?;
                    persisted_certificate = decrypted_certificate_maybe;
                }
            };

            if persisted_certificate.is_none() {
                log::info!("[ACME] Certificate not found, sleeping for 5 seconds");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }

        if let Some(persisted_certificate) = persisted_certificate {
            log::info!("[ACME] Certificate found after polling");
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
        enclave_context: &EnclaveContext,
    ) -> Result<Option<CertifiedKey>, AcmeError> {
        let raw_acme_certificate =
            match RawAcmeCertificate::from_storage(self.config_client.clone()).await? {
                Some(cert) => cert,
                None => return Ok(None),
            };

        log::info!("[ACME] Certificate found in storage");

        let decrypted_certificate =
            Self::decrypt_certificate(&self.e3_client, &raw_acme_certificate).await?;
        let x509s = decrypted_certificate.to_x509s()?;
        let time_till_renewal_required =
            decrypted_certificate.time_till_renewal_required(x509s.clone())?;

        self.schedule_certificate_renewal(
            time_till_renewal_required,
            key.clone(),
            enclave_context.clone(),
        )
        .await?;

        Some(decrypted_certificate.to_certified_key(x509s, key)).transpose()
    }

    async fn schedule_certificate_renewal(
        &self,
        time_till_renewal: Duration,
        key: PKey<Private>,
        enclave_context: EnclaveContext,
    ) -> Result<(), AcmeError> {
        let self_clone = self.clone();

        tokio::spawn(async move {
            tokio::time::sleep(time_till_renewal).await;

            //Retry certificate renewal if it fails
            let retries = 3;
            for _ in 0..retries {
                if let Err(e) = self_clone
                    .renew_certificate_and_update_store(key.clone(), &enclave_context)
                    .await
                {
                    log::error!("[ACME] Error renewing certificate: {:?}", e);
                } else {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn renew_certificate_and_update_store(
        &self,
        key: PKey<Private>,
        enclave_context: &EnclaveContext,
    ) -> Result<(), AcmeError> {
        let order_lock_maybe = Self::get_order_lock().await?;
        let attempts = order_lock_maybe
            .as_ref()
            .map_or(0, |lock| lock.number_of_attempts().unwrap_or(0));

        if Self::order_lock_exists_and_is_valid(&order_lock_maybe)? {
            log::info!("[ACME] Lock is valid, waiting for Certificate to be created by other instance or waiting for lock to expire");
            // If the lock is valid, do nothing and wait for the certificate to be renewed by another instance or for the lock to expire.
            return Ok(());
        }

        match self
            .clone()
            .create_certificate_and_persist_with_lock(key, enclave_context, attempts + 1)
            .await
        {
            Ok(Some(cert)) => {
                if let Err(e) = TRUSTED_CERT_STORE
                    .try_write()
                    .map(|mut store| *store = Some(cert))
                {
                    log::error!("[ACME] Error updating trusted certificate store: {:?}", e);
                    Err(AcmeError::General(
                        "Error updating trusted certificate store".into(),
                    ))
                } else {
                    Ok(())
                }
            }
            _ => {
                log::error!("[ACME] Error renewing certificate. Not updating trusted certificate store: {:?}", e);
                Err(AcmeError::General("Error renewing certificate".into()))
            }
        }
    }

    async fn get_order_lock() -> Result<Option<StorageLock>, AcmeError> {
        let order_lock_maybe = StorageLock::read_from_storage(CERTIFICATE_LOCK_NAME.into()).await?;
        match order_lock_maybe {
            Some(lock) => Ok(Some(lock)),
            None => Ok(None),
        }
    }

    fn order_lock_exists_and_is_valid(lock_maybe: &Option<StorageLock>) -> Result<bool, AcmeError> {
        match lock_maybe {
            Some(lock) => Ok(!lock.is_expired()),
            None => Ok(false),
        }
    }

    async fn create_certificate_and_persist_with_lock(
        &mut self,
        key: PKey<Private>,
        enclave_context: &EnclaveContext,
        attempts: u32,
    ) -> Result<Option<CertifiedKey>, AcmeError> {
        let certificate_lock = StorageLock::new_with_config_client(
            CERTIFICATE_LOCK_NAME.into(),
            attempts,
            self.config_client.clone(),
        );
        if certificate_lock.write_and_check_persisted().await? {
            let cert_domains = enclave_context.get_trusted_cert_domains();

            //Try twice with LetsEncrypt, then try with ZeroSSL
            let provider = if attempts <= 2 {
                Provider::LetsEncrypt
            } else {
                Provider::ZeroSSL
            };

            let raw_acme_certificate = self
                .order_certificate(cert_domains, key.clone(), provider.clone())
                .await;

            if let Err(e) = raw_acme_certificate {
                StatsClient::record_cert_order(provider.get_stats_key(), false);
                log::error!(
                    "[ACME] Error ordering certificate: {:?}. Provider: {:?}",
                    e,
                    provider
                );
                certificate_lock.delete().await?;
                return Err(e);
            } else {
                StatsClient::record_cert_order(provider.get_stats_key(), true);
            }

            let acme_certificate = raw_acme_certificate?;

            let encrypted_raw_certificate =
                Self::encrypt_certificate(&self.e3_client, &acme_certificate).await?;

            encrypted_raw_certificate
                .persist(&self.config_client)
                .await?;

            certificate_lock.delete().await?;

            let x509s = acme_certificate.to_x509s()?;

            Ok(Some(acme_certificate.to_certified_key(x509s, key)?))
        } else {
            Ok(None)
        }
    }

    async fn init_acme_account(
        &self,
        provider: &Provider,
    ) -> Result<Arc<Account<AcmeClient>>, AcmeError> {
        let server_name = ServerName::try_from(provider.hostname()).expect("Hardcoded hostname");
        let acme_client = AcmeClient::new(server_name);

        let directory =
            Directory::fetch_directory(acme_client, self.config_client.clone(), provider.clone())
                .await?;

        let eab_required = provider.eab_required();

        let acme_account = AccountBuilder::new(directory, eab_required, provider.clone())
            .contact(vec![String::from("mailto:engineering@evervault.com")])
            .terms_of_service_agreed(true)
            .build()
            .await?;

        Ok(acme_account)
    }

    //Use all the acme libraries to order cert
    async fn order_certificate(
        &mut self,
        domains: Vec<String>,
        key: PKey<Private>,
        provider: Provider,
    ) -> Result<RawAcmeCertificate, AcmeError> {
        log::info!("[ACME] Initializing acme account. Provider: {:?}", provider);

        let acme_account = match self.acme_account {
            Some(ref acme_account) => acme_account.clone(),
            None => {
                let new_account = self.init_acme_account(&provider).await?;
                self.acme_account = Some(new_account.clone());
                new_account
            }
        };

        let mut order_builder = OrderBuilder::new(acme_account);

        for domain in domains.iter() {
            order_builder.add_dns_identifier(domain.to_string());
        }

        log::info!("[ACME] Creating order for trusted cert.");
        let order = order_builder.build(provider).await?;

        log::info!("[ACME] Fetching authorizations needed for order.");
        let authorizations = order.authorizations().await?;

        log::info!(
            "[ACME] {} authorizations needed. Storing challenges.",
            authorizations.len()
        );
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

        log::info!(
            "[ACME] All authorizations validated. Continuing polling order to check if ready."
        );

        let order_ready = order.wait_ready(Duration::from_secs(5), 5).await?;

        log::info!("[ACME] Order is ready. Finalizing order.");

        let order_finalized = order_ready.finalize(key).await?;

        let order_complete = order_finalized.wait_done(Duration::from_secs(5), 5).await?;

        log::info!("[ACME] Order is complete. Downloading certficate.");

        let cert_chain: Vec<X509> =
            order_complete
                .certificate()
                .await?
                .ok_or(AcmeError::FieldNotFound(
                    "Certificate not found in completed order".into(),
                ))?;

        log::info!("[ACME] Certificate received!");

        RawAcmeCertificate::from_x509s(cert_chain)
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
            .encrypt(
                CryptoRequest {
                    data: json!(raw_acme_certificate),
                },
                None,
            )
            .await?;

        let encrypted_acme_key_pair: RawAcmeCertificate = serde_json::from_value(e3_response.data)?;

        Ok(encrypted_acme_key_pair)
    }
}
