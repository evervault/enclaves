use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

use serde_json::json;
use tokio_rustls::rustls::{sign::CertifiedKey, ServerName};

use crate::{
    config_client::{ConfigClient, StorageConfigClientInterface},
    e3client::{CryptoRequest, CryptoResponse, E3Api, E3Client},
    server::tls::trusted_cert_container::TRUSTED_CERT_STORE,
    stats::client::StatsClient,
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
    raw_cert::RawAcmeCertificate,
    utils,
};

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
                        "[ACME] No valid lock on ACME ordering, creating lock and certificate. {attempts} attempt(s) made."
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

                    let sixty_days_from_now =
                        SystemTime::now() + Duration::from_secs(utils::SIXTY_DAYS_IN_SECONDS);
                    let time_for_renewal = utils::get_jittered_time(sixty_days_from_now);
                    let time_till_renewal = time_for_renewal.duration_since(SystemTime::now())?;

                    self.schedule_certificate_renewal(
                        time_till_renewal,
                        key.clone(),
                        enclave_context.clone(),
                    );
                }
            };

            if persisted_certificate.is_none() {
                log::info!("[ACME] Certificate not found, sleeping for 5 seconds");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }

        if let Some(persisted_certificate) = persisted_certificate {
            log::info!("[ACME] Certificate found after polling");
            Self::write_certificate_to_rwlock(persisted_certificate.clone())?;
            Ok(persisted_certificate)
        } else {
            Err(AcmeError::General(
                "[ACME] Certificate not found after polling".into(),
            ))
        }
    }

    async fn fetch_certificate_and_renewal_time(
        &self,
        key: PKey<Private>,
    ) -> Result<Option<(CertifiedKey, Duration)>, AcmeError> {
        let raw_acme_certificate =
            match RawAcmeCertificate::from_storage(self.config_client.clone()).await {
                Ok(Some(cert)) => {
                    log::info!("[ACME] Certificate found in storage");
                    cert
                }
                Ok(None) => return Ok(None),
                Err(e) => return Err(e),
            };

        let decrypted_certificate =
            Self::decrypt_certificate(&self.e3_client, &raw_acme_certificate).await?;
        let x509s = decrypted_certificate.to_x509s()?;
        let time_till_renewal_required =
            decrypted_certificate.time_till_renewal_required(x509s.clone())?;

        let certified_key = decrypted_certificate.to_certified_key(x509s, key)?;

        Ok(Some((certified_key, time_till_renewal_required)))
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
        );

        Some(decrypted_certificate.to_certified_key(x509s, key)).transpose()
    }

    fn schedule_certificate_renewal(
        &self,
        time_till_renewal: Duration,
        key: PKey<Private>,
        enclave_context: EnclaveContext,
    ) {
        let self_clone = self.clone();

        log::info!(
            "[ACME] Certificate renewal scheduled {:?} seconds from now",
            time_till_renewal.as_secs()
        );

        tokio::spawn(async move {
            tokio::time::sleep(time_till_renewal).await;

            if let Ok(Some((cert, time_till_expiry))) = self_clone
                .fetch_certificate_and_renewal_time(key.clone())
                .await
            {
                if time_till_expiry.as_secs() > utils::SIXTY_DAYS_IN_SECONDS {
                    log::info!("[ACME] Certificate has already being renewed by other instance.");
                    if let Err(err) = Self::write_certificate_to_rwlock(cert) {
                        log::error!(
                            "[ACME] Error writing renewed certificate to trusted certificate store: {err:?}")
                    } else {
                        return;
                    }
                }
            }

            //Retry certificate renewal if it fails
            let retries = 3;
            let mut delay_in_seconds = 10;
            let mut last_error: Option<AcmeError> = None;
            for i in 1..retries {
                if let Err(e) = self_clone
                    .renew_certificate_and_update_store(key.clone(), &enclave_context)
                    .await
                {
                    log::error!("[ACME] Error renewing certificate: {e:?}");
                    last_error = Some(e);
                } else {
                    log::info!("[ACME] Certificate renewed successfully.");
                    last_error = None;
                    break;
                }
                delay_in_seconds *= i;
                tokio::time::sleep(Duration::from_secs(delay_in_seconds)).await;
            }

            let days_till_renewal = if let Some(e) = last_error {
                log::error!(
                    "[ACME] Error renewing certificate after retries: {e:?}. Scheduling next renewal for tomorrow."
                );
                utils::ONE_DAY_IN_SECONDS
            } else {
                log::info!("[ACME] Scheduling next renewal for 60 days from now");
                utils::SIXTY_DAYS_IN_SECONDS
            };

            if let Ok(time_till_renewal) = utils::seconds_with_jitter_to_time(days_till_renewal) {
                self_clone.schedule_certificate_renewal(time_till_renewal, key, enclave_context);
            };
        });
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
            Ok(Some(cert)) => Self::write_certificate_to_rwlock(cert),
            _ => {
                log::error!(
                    "[ACME] Error renewing certificate. Not updating trusted certificate store"
                );
                Err(AcmeError::General("Error renewing certificate".into()))
            }
        }
    }

    async fn get_order_lock() -> Result<Option<StorageLock>, AcmeError> {
        let order_lock_maybe =
            StorageLock::read_from_storage(utils::CERTIFICATE_LOCK_NAME.into()).await?;
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
            utils::CERTIFICATE_LOCK_NAME.into(),
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
                    "[ACME] Error ordering certificate: {e:?}. Provider: {provider:?}"
                );
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
        log::info!("[ACME] Initializing acme account. Provider: {provider:?}");

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

            let path = format!("acme-challenges/{token}");

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
                .wait_done(Duration::from_secs(10), 7)
                .await?;

            auth.wait_done(Duration::from_secs(10), 7).await?;
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

    fn write_certificate_to_rwlock(cert: CertifiedKey) -> Result<(), AcmeError> {
        match TRUSTED_CERT_STORE.write() {
            Ok(mut store) => {
                *store = Some(cert);
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "[ACME] Error acquiring write lock on trusted certificate store: {e:?}"
                );
                Err(AcmeError::General(
                    "Error acquiring write lock on trusted certificate store".into(),
                ))
            }
        }
    }
}
