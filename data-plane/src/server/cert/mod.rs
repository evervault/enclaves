mod self_signed;
pub use self_signed::SelfSignedCertProvider;

use crate::server::error::ServerResult;
use async_trait::async_trait;
use tokio_rustls::rustls::{Certificate, PrivateKey};

#[async_trait]
pub(super) trait CertProvider {
    async fn get_cert_and_key(&self) -> ServerResult<(Certificate, PrivateKey)>;
}
