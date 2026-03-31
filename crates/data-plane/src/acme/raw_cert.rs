use std::{
    str::from_utf8,
    time::{Duration, SystemTime},
};

use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::X509,
};

use crate::config_client::{ConfigClient, StorageConfigClientInterface};

use super::{error::AcmeError, utils};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{
    sign::{self, CertifiedKey},
    Certificate, PrivateKey,
};

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

    pub fn convert_to_pemfile(certificates: Vec<X509>) -> Result<String, AcmeError> {
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
            .get_object(utils::CERTIFICATE_OBJECT_KEY.into())
            .await?;

        let parsed_response =
            response_maybe.map(|response| RawAcmeCertificate::new(response.body()));

        Ok(parsed_response)
    }

    pub fn to_x509s(&self) -> Result<Vec<X509>, AcmeError> {
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

            let time_till_expiry_converted = utils::asn1_time_to_system_time(earliest_expiry)?;
            let thirty_days_before_expiry =
                time_till_expiry_converted - Duration::from_secs(utils::THIRTY_DAYS_IN_SECONDS);

            let time_to_renew_with_jitter = utils::get_jittered_time(thirty_days_before_expiry);
            let time_till_renewal = time_to_renew_with_jitter.duration_since(SystemTime::now())?;
            return Ok(time_till_renewal);
        }

        //If failed to get expiry, renew straight away as cert must be corrupted
        Ok(Duration::from_secs(0))
    }

    pub fn to_certified_key(
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
            .put_object(
                utils::CERTIFICATE_OBJECT_KEY.into(),
                self.certificate.clone(),
            )
            .await?;

        Ok(())
    }
}
