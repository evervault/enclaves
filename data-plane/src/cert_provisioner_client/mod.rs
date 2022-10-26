mod tls_verifier;

use hyper::{Body, Response};
use serde::de::DeserializeOwned;
use shared::server::config_server::requests::{ConfigServerPayload, GetCertRequestDataPlane};
use tokio_rustls::rustls::ServerName;
use tokio_rustls::TlsConnector;

use crate::base_tls_client::tls_client_config::get_tls_client_config;
use crate::base_tls_client::{BaseClient, ClientError};
use crate::configuration;
#[cfg(feature = "enclave")]
use crate::crypto::attest;

type CertProvisionerError = ClientError;
pub struct CertProvisionerClient {
    base_client: BaseClient,
}

impl Default for CertProvisionerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CertProvisionerClient {
    pub fn new() -> Self {
        let verifier = std::sync::Arc::new(tls_verifier::CertProvisionerCertVerifier);
        let tls_connector =
            TlsConnector::from(std::sync::Arc::new(get_tls_client_config(verifier)));

        let server_name = ServerName::try_from(configuration::get_cert_provisioner_host().as_str())
            .expect("Hardcoded hostname");

        Self {
            base_client: BaseClient::new(tls_connector, server_name, shared::ENCLAVE_CERT_PORT),
        }
    }

    fn uri(&self, path: &str) -> String {
        format!(
            "https://{}:{}{}",
            configuration::get_cert_provisioner_host(),
            shared::ENCLAVE_CERT_PORT,
            path
        )
    }

    fn get_attestation_doc(&self, token: String) -> Result<String, CertProvisionerError> {
        let token_bytes = token.as_bytes().to_vec();

        #[cfg(feature = "enclave")]
        let attestation_doc = attest::get_attestation_doc(Some(token_bytes), None)
            .map_err(|err| CertProvisionerError::General(err.to_string()))?;

        #[cfg(not(feature = "enclave"))]
        let attestation_doc: Vec<u8> = token_bytes;

        let base64_doc = base64::encode(attestation_doc);

        Ok(base64_doc)
    }

    pub async fn get_cert(
        &self,
        token: String,
    ) -> Result<GetCertRequestDataPlane, CertProvisionerError> {
        let attestation_doc = self.get_attestation_doc(token)?;

        let body = GetCertRequestDataPlane::new(attestation_doc)
            .into_body()
            .map_err(|err| CertProvisionerError::General(err.to_string()))?;

        let response = self
            .base_client
            .send(None, "POST", &self.uri("/cert"), body)
            .await?;

        self.parse_response(response).await
    }

    async fn parse_response<T: DeserializeOwned>(
        &self,
        res: Response<Body>,
    ) -> Result<T, CertProvisionerError> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body).await?;
        Ok(serde_json::from_slice(&response_body)?)
    }
}
