use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
#[cfg(not(feature = "enclave"))]
use std::time::Duration;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::sign::{self, CertifiedKey};
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub static TRUSTED_CERT_STORE: Lazy<Arc<RwLock<Option<CertifiedKey>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));
