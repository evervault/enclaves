use crate::acme::error::*;
use crate::acme::provider::Provider;
use crate::config_client::ConfigClient;
use crate::configuration;
use hyper::Body;
use hyper::Response;
use serde::Deserialize;
use serde_json::Value;
use shared::acme::jws::JwsResult;
use std::str::from_utf8;
use std::sync::Arc;
use std::sync::Mutex;

use super::client::AcmeClientInterface;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct Directory<T: AcmeClientInterface> {
    #[serde(skip)]
    pub client: T,
    #[serde(skip)]
    pub config_client: ConfigClient,
    #[serde(skip)]
    pub nonce: Mutex<Option<String>>,
    #[serde(rename = "newNonce")]
    pub new_nonce_url: String,
    #[serde(rename = "newAccount")]
    pub new_account_url: String,
    #[serde(rename = "newOrder")]
    pub new_order_url: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert_url: String,
    #[serde(rename = "keyChange")]
    pub key_change_url: Option<String>,
    #[serde(rename = "newAuthz")]
    pub new_authz_url: Option<String>,
    /// Optional metadata describing a directory.
    pub meta: Option<DirectoryMeta>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

fn extract_nonce_from_response(
    resp: &hyper::Response<hyper::Body>,
) -> Result<Option<String>, AcmeError> {
    resp.headers()
        .get("replay-nonce")
        .map(|nonce| {
            nonce
                .to_str()
                .map(|s| s.to_string())
                .map_err(AcmeError::HeaderConversionError)
        })
        .transpose()
}

impl<T: AcmeClientInterface + std::default::Default> Directory<T> {
    pub async fn fetch_directory(
        acme_http_client: T,
        config_client: ConfigClient,
        provider: Provider,
    ) -> Result<Arc<Directory<T>>, AcmeError> {
        let host = provider.hostname();
        let path = provider.directory_path();
        let url = format!("https://{}{}", host, path);

        let request = hyper::Request::builder()
            .method("GET")
            .uri(url)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::HOST, host)
            .body(Body::empty())?;

        let resp: Response<Body> = acme_http_client.send(request).await?;
        let resp_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;

        let mut directory: Directory<_> =
            serde_json::from_str(body_str).expect("Failed to deserialize Directory");

        directory.client = acme_http_client;
        directory.config_client = config_client;
        directory.nonce = Mutex::new(None);

        Ok(Arc::new(directory))
    }

    pub async fn get_nonce(&self, provider: Provider) -> Result<String, AcmeError> {
        let maybe_nonce = {
            let mut guard = self
                .nonce
                .lock()
                .map_err(|err| AcmeError::General(err.to_string()))?;
            guard.take()
        };

        if let Some(nonce) = maybe_nonce {
            return Ok(nonce);
        }

        let new_nonce_request = hyper::Request::builder()
            .method("GET")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::HOST, provider.hostname())
            .uri(&self.new_nonce_url)
            .body(Body::empty())?;

        let resp = self.client.send(new_nonce_request).await?;

        let maybe_nonce = extract_nonce_from_response(&resp)?;

        maybe_nonce.ok_or(AcmeError::NoNonce)
    }

    async fn authenticated_request_raw(
        &self,
        method: &str,
        url: &str,
        payload: &str,
        account_id: &Option<String>,
        provider: Provider,
    ) -> Result<hyper::Response<Body>, AcmeError> {
        let nonce = self.get_nonce(provider).await?;
        let result = &self
            .config_client
            .jws(
                shared::server::config_server::requests::SignatureType::ECDSA,
                url.into(),
                Some(nonce.clone()),
                payload.into(),
                account_id.clone(),
            )
            .await?;

        let body: JwsResult = result.into();

        let body = serde_json::to_vec(&body)?;

        let request = hyper::Request::builder()
            .method(method)
            .uri(url)
            .header(hyper::header::HOST, configuration::get_acme_host())
            .header(hyper::header::CONTENT_TYPE, "application/jose+json")
            .body(Body::from(body))?;

        let resp1 = self.client.send(request).await;

        let resp = resp1?;

        if !resp.status().is_success() {
            let resp_body = hyper::body::to_bytes(resp.into_body()).await?;
            let body_str = from_utf8(&resp_body)?;
            log::error!(
                "Error response from authenticated request to {}: {}",
                url,
                body_str
            );
            Err(AcmeError::ClientError(body_str.to_string()))
        } else {
            if let Some(nonce) = extract_nonce_from_response(&resp)? {
                let mut guard = self
                    .nonce
                    .lock()
                    .map_err(|err| AcmeError::PoisonError(err.to_string()))?;
                *guard = Some(nonce);
            }

            Ok(resp)
        }
    }

    pub async fn authenticated_request(
        &self,
        url: &str,
        method: &str,
        payload: Option<Value>,
        account_id: &Option<String>,
        provider: Provider,
    ) -> Result<hyper::Response<Body>, AcmeError> {
        //Handle empty body
        let payload_parsed = match payload {
            None => "".to_string(),
            Some(payload) => serde_json::to_string(&payload)?,
        };

        log::info!("[ACME] Sending authenticated request to {}", url);

        let resp_result = self
            .authenticated_request_raw(method, url, &payload_parsed, account_id, provider)
            .await;

        if let Err(err) = &resp_result {
            log::error!(
                "[ACME] Error sending authenticated request to {}: Error: {}",
                url,
                err
            );
            return resp_result;
        };

        let resp = resp_result?;

        if let Some(nonce) = extract_nonce_from_response(&resp)? {
            let mut guard: std::sync::MutexGuard<'_, Option<String>> = self
                .nonce
                .lock()
                .map_err(|err| AcmeError::PoisonError(err.to_string()))?;
            *guard = Some(nonce);
        }

        Ok(resp)
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        acme::{mocks::client_mock::MockAcmeClientInterface, provider},
        config_client,
    };

    pub struct TestDirectoryPaths {
        pub new_nonce_url: String,
        pub new_account_url: String,
        pub new_order_url: String,
        pub revoke_cert_url: String,
        pub key_change_url: Option<String>,
        pub new_authz_url: Option<String>,
        pub meta_terms_of_service: Option<String>,
        pub meta_website: Option<String>,
        pub meta_caa_identities: Option<Vec<String>>,
        pub meta_external_account_required: Option<bool>,
    }

    impl TestDirectoryPaths {
        pub fn new() -> Self {
            Self {
                new_nonce_url: String::from("https://example.com/acme/new-nonce"),
                new_account_url: String::from("https://example.com/acme/new-account"),
                new_order_url: String::from("https://example.com/acme/new-order"),
                revoke_cert_url: String::from("https://example.com/acme/revoke-cert"),
                key_change_url: Some(String::from("https://example.com/acme/key-change")),
                new_authz_url: Some(String::from("https://example.com/acme/new-authz")),
                meta_terms_of_service: Some(String::from(
                    "https://example.com/acme/terms/2017-12-01",
                )),
                meta_website: Some(String::from("https://example.com/")),
                meta_caa_identities: Some(vec![String::from("example.com")]),
                meta_external_account_required: Some(true),
            }
        }
    }

    fn get_test_directory<T: AcmeClientInterface>(
        client: T,
        config_client: ConfigClient,
        nonce_value: Option<String>,
    ) -> Directory<T> {
        let test_directory_paths = TestDirectoryPaths::new();
        let nonce = Mutex::new(nonce_value);
        let meta = DirectoryMeta {
            terms_of_service: test_directory_paths.meta_terms_of_service,
            website: test_directory_paths.meta_website,
            caa_identities: test_directory_paths.meta_caa_identities,
            external_account_required: test_directory_paths.meta_external_account_required,
        };

        Directory {
            client,
            config_client,
            nonce,
            new_nonce_url: test_directory_paths.new_nonce_url,
            new_account_url: test_directory_paths.new_account_url,
            new_order_url: test_directory_paths.new_order_url,
            revoke_cert_url: test_directory_paths.revoke_cert_url,
            key_change_url: test_directory_paths.key_change_url,
            new_authz_url: test_directory_paths.new_authz_url,
            meta: Some(meta),
        }
    }

    #[tokio::test]
    async fn test_directory_fetch() {
        let mut mock_client = MockAcmeClientInterface::new();
        let test_config_client = config_client::ConfigClient::new();
        let test_directory_paths = TestDirectoryPaths::new();
        mock_client.expect_send().returning(|_| {
            let resp = hyper::Response::builder()
                .status(200)
                .body(Body::from(
                    r#"{
                        "newNonce": "https://example.com/acme/new-nonce",
                        "newAccount": "https://example.com/acme/new-account",
                        "newOrder": "https://example.com/acme/new-order",
                        "revokeCert": "https://example.com/acme/revoke-cert",
                        "keyChange": "https://example.com/acme/key-change",
                        "meta": {
                            "termsOfService": "https://example.com/acme/terms/2017-12-01",
                            "website": "https://example.com/",
                            "caaIdentities": [
                                "example.com"
                            ],
                            "externalAccountRequired": true
                        }
                    }"#,
                ))
                .unwrap();
            Ok(resp)
        });

        let directory =
            Directory::fetch_directory(mock_client, test_config_client, Provider::LetsEncrypt)
                .await
                .unwrap();

        assert_eq!(directory.new_nonce_url, test_directory_paths.new_nonce_url);
        assert_eq!(
            directory.new_account_url,
            test_directory_paths.new_account_url
        );
        assert_eq!(directory.new_order_url, test_directory_paths.new_order_url);
        assert_eq!(
            directory.revoke_cert_url,
            test_directory_paths.revoke_cert_url
        );
        assert_eq!(
            directory.key_change_url,
            test_directory_paths.key_change_url
        );
        assert_eq!(
            directory.meta.as_ref().unwrap().terms_of_service,
            test_directory_paths.meta_terms_of_service
        );
        assert_eq!(
            directory.meta.as_ref().unwrap().website,
            test_directory_paths.meta_website
        );
        assert_eq!(
            directory.meta.as_ref().unwrap().caa_identities,
            test_directory_paths.meta_caa_identities
        );
        assert_eq!(
            directory.meta.as_ref().unwrap().external_account_required,
            test_directory_paths.meta_external_account_required
        );
    }

    #[tokio::test]
    async fn test_get_nonce_first_time() {
        let mut mock_client = MockAcmeClientInterface::new();
        let test_config_client = config_client::ConfigClient::new();

        mock_client.expect_send().returning(|_| {
            let resp = hyper::Response::builder()
                .status(200)
                .header("replay-nonce", "1234567890")
                .body(Body::empty())
                .unwrap();
            Ok(resp)
        });

        let test_directory = get_test_directory(mock_client, test_config_client, None);

        let nonce = test_directory.get_nonce().await.unwrap();

        assert_eq!(nonce, "1234567890");
    }

    #[tokio::test]
    async fn test_get_nonce_exists() {
        let mut mock_client = MockAcmeClientInterface::new();
        let test_config_client = config_client::ConfigClient::new();

        mock_client.expect_send().times(0);

        let test_directory = get_test_directory(
            mock_client,
            test_config_client,
            Some(String::from("987654321")),
        );

        let nonce = test_directory.get_nonce().await.unwrap();

        assert_eq!(nonce, "987654321");
    }
}
