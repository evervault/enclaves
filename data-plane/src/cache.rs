use std::sync::RwLock;

use cached::TimedSizedCache;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::crypto::token::AttestationAuth;

const E3_TOKEN_LIFETIME: u64 = 280;

pub static E3_TOKEN: Lazy<Mutex<TimedSizedCache<String, AttestationAuth>>> = Lazy::new(|| {
    Mutex::new(TimedSizedCache::with_size_and_lifespan(
        1,
        E3_TOKEN_LIFETIME,
    ))
});

pub struct TrustedCertStore {
    trusted_cert: Option<CertifiedKey>,
    cage_initliazed_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl TrustedCertStore {
    pub fn new() -> Self {
        Self {
            trusted_cert: None,
            cage_initliazed_time: None,
        }
    }

    pub fn get_trusted_cert(&self) -> Option<CertifiedKey> {
        self.trusted_cert.clone()
    }

    pub fn set_trusted_cert(&mut self, trusted_cert: CertifiedKey) {
        self.trusted_cert = Some(trusted_cert);
    }

    pub fn get_initialized_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.cage_initliazed_time.clone()
    }

    pub fn set_initialized_time(&mut self, time: chrono::DateTime<chrono::Utc>) {
        self.cage_initliazed_time = Some(time);
    }
}

pub static TRUSTED_CERT_STORE: Lazy<RwLock<TrustedCertStore>> =
    Lazy::new(|| RwLock::new(TrustedCertStore::new()));
