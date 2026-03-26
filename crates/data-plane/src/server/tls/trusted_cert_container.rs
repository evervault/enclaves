use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use tokio_rustls::rustls::sign::CertifiedKey;

pub static TRUSTED_CERT_STORE: Lazy<Arc<RwLock<Option<CertifiedKey>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));
