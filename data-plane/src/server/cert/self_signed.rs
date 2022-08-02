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

        #[cfg(feature = "enclave")]
        let self_signed_cert = ra_tls::inject_attestation_into_cert(self_signed_cert)?;

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

#[cfg(feature = "enclave")]
mod ra_tls {
    use super::*;
    use crate::crypto::{attest, common};
    use rcgen::{CertificateParams, CustomExtension, KeyPair};

    pub fn inject_attestation_into_cert(
        cert: SelfSignedCertificate,
    ) -> ServerResult<SelfSignedCertificate> {
        println!("Adding attestation document to the enclave cert");
        let public_key = cert.get_key_pair().public_key_der();
        let hashed_pub_key = common::compute_sha256(public_key);
        let attestation_doc = attest::get_attestation_doc(hashed_pub_key)?;
        println!("Attestation doc received");
        let ra_tls_cert = rebuild_cert_with_extension(cert, attestation_doc)?;
        println!("Cert rebuilt with attestation document");
        Ok(ra_tls_cert)
    }

    const ATTESTATION_OID: [u64; 12] = [
        0x02, 0x04, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x05,
    ];
    pub fn rebuild_cert_with_extension(
        cert: SelfSignedCertificate,
        attestation_doc: Vec<u8>,
    ) -> ServerResult<SelfSignedCertificate> {
        let cert_key_pair = cert.get_key_pair().serialize_der();
        let reconstructred_key_pair = KeyPair::from_der(cert_key_pair.as_slice())?;
        let mut params = CertificateParams::from_ca_cert_der(
            cert.serialize_der()?.as_slice(),
            reconstructred_key_pair,
        )?;
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &ATTESTATION_OID,
                attestation_doc,
            ));
        Ok(SelfSignedCertificate::from_params(params)?)
    }
}
