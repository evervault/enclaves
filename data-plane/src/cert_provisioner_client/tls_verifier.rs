use std::time::SystemTime;
use tokio_rustls::rustls::client::ServerCertVerifier;
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerName},
    Certificate, CertificateError, Error,
};

use crate::configuration;

pub struct CertProvisionerCertVerifier;

impl ServerCertVerifier for CertProvisionerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert_provisioner_hostname = configuration::get_cert_provisioner_host();
        let expected_server_name =
            ServerName::try_from(cert_provisioner_hostname.as_str()).expect("Infallible");

        if &expected_server_name == server_name {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(CertificateError::NotValidForName))
        }
    }
}
