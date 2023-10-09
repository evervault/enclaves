use std::sync::Arc;

use tokio_rustls::rustls::client::ServerCertVerifier;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor};

pub fn get_tls_client_config(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    let config_builder = tokio_rustls::rustls::ClientConfig::builder().with_safe_defaults();
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let mut client_config = config_builder
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let mut dangerous = client_config.dangerous();
    dangerous.set_certificate_verifier(verifier);
    client_config
}
