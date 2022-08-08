use std::time::SystemTime;
use tokio_rustls::rustls::client::ServerCertVerifier;
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerName},
    Certificate, Error,
};

pub struct E3CertVerifier;

impl ServerCertVerifier for E3CertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        // TODO: add assertions on E3's cert
        Ok(ServerCertVerified::assertion())
    }
}
