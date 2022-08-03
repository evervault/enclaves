use super::async_trait;

#[cfg(feature = "enclave")]
use rcgen::{CertificateParams, CustomExtension, KeyPair};

use super::{CertProvider, ServerResult};
use rcgen::Certificate as SelfSignedCertificate;
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub struct SelfSignedCertProvider {
    cert: SelfSignedCertificate,
}

impl SelfSignedCertProvider {
    pub fn new<T: Into<Vec<String>>>(alt_names: T) -> ServerResult<Self> {
        let self_signed_cert = rcgen::generate_simple_self_signed(alt_names)?;

        Ok(Self {
            cert: self_signed_cert,
        })
    }
}

#[async_trait]
impl CertProvider for SelfSignedCertProvider {
    async fn get_cert_and_key(&self) -> ServerResult<(Certificate, PrivateKey)> {
        let cert = Certificate(self.cert.serialize_der()?);
        let private_key = PrivateKey(self.cert.serialize_private_key_der());
        Ok((cert, private_key))
    }
}
