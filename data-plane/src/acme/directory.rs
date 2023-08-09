use crate::acme::error::*;
// use crate::acme::jws::jws;
use hyper::Body;
use serde::Deserialize;
use serde_json::from_slice;
use std::sync::Arc;
use std::sync::Mutex;

use super::client::AcmeClientInterface;

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct Directory<T: AcmeClientInterface> {
  #[serde(skip)]
  pub client: T,
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
    resp: hyper::Response<hyper::Body>,
) -> Result<Option<String>, AcmeError> {
    resp.headers()
        .get("replay-nonce")
        .map(|nonce| nonce.to_str()
            .map(|s| s.to_string())
            .map_err(AcmeError::HeaderConversionError))
        .transpose()
}


impl <T: AcmeClientInterface + Default> Directory<T> {

    pub async fn fetch_directory(url: String, acme_http_client: T) -> Result<Arc<Directory<T>>, AcmeError> {
        let request = hyper::Request::builder()
        .method("GET")
        .uri(url)
        .body(Body::empty())?;

        let resp = acme_http_client.send(request).await?;

        let resp_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let mut directory: Directory<T> = from_slice(&resp_bytes)?;

        directory.client = acme_http_client;
        directory.nonce = Mutex::new(None);

    Ok(Arc::new(directory))    
    }

  pub async fn get_nonce(&self) -> Result<String, AcmeError> {
    let maybe_nonce = {
      let mut guard = self.nonce.lock().map_err(|err| AcmeError::General(err.to_string()))?;
      guard.take()
    };

    if let Some(nonce) = maybe_nonce {
      return Ok(nonce);
    }

    let new_nonce_request = hyper::Request::builder()
      .method("GET")
      .uri(&self.new_nonce_url)
      .body(Body::empty())?;

    let resp = self.client.send(new_nonce_request).await?;
    
    let maybe_nonce = extract_nonce_from_response(resp)?;

    maybe_nonce.ok_or(AcmeError::NoNonce)
  }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::acme::mocks::client_mock::MockAcmeClientInterface;

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
                meta_terms_of_service: Some(String::from("https://example.com/acme/terms/2017-12-01")),
                meta_website: Some(String::from("https://example.com/")),
                meta_caa_identities: Some(vec![String::from("example.com")]),
                meta_external_account_required: Some(true)
            }
        }
    }

    fn get_test_directory<T: AcmeClientInterface>(client: T, nonce_value: Option<String>) -> Directory<T> {
        let test_directory_paths = TestDirectoryPaths::new();
        let nonce = Mutex::new(nonce_value);
        let meta = DirectoryMeta {
            terms_of_service: test_directory_paths.meta_terms_of_service,
            website: test_directory_paths.meta_website,
            caa_identities: test_directory_paths.meta_caa_identities,
            external_account_required: test_directory_paths.meta_external_account_required
        };

        Directory {
            client,
            nonce,
            new_nonce_url: test_directory_paths.new_nonce_url,
            new_account_url: test_directory_paths.new_account_url,
            new_order_url: test_directory_paths.new_order_url,
            revoke_cert_url: test_directory_paths.revoke_cert_url,
            key_change_url: test_directory_paths.key_change_url,
            new_authz_url: test_directory_paths.new_authz_url,
            meta: Some(meta)
        }
    }

    #[tokio::test]
    async fn test_directory_fetch() {
        let mut mock_client = MockAcmeClientInterface::new();
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

        let directory = Directory::fetch_directory(String::from("https://example.com/acme/directory"), mock_client).await.unwrap();

        assert_eq!(directory.new_nonce_url, test_directory_paths.new_nonce_url);
        assert_eq!(directory.new_account_url, test_directory_paths.new_account_url);
        assert_eq!(directory.new_order_url, test_directory_paths.new_order_url);
        assert_eq!(directory.revoke_cert_url, test_directory_paths.revoke_cert_url);
        assert_eq!(directory.key_change_url, test_directory_paths.key_change_url);
        assert_eq!(directory.meta.as_ref().unwrap().terms_of_service, test_directory_paths.meta_terms_of_service);
        assert_eq!(directory.meta.as_ref().unwrap().website, test_directory_paths.meta_website);
        assert_eq!(directory.meta.as_ref().unwrap().caa_identities, test_directory_paths.meta_caa_identities);
        assert_eq!(directory.meta.as_ref().unwrap().external_account_required, test_directory_paths.meta_external_account_required);
    }

    #[tokio::test]
    async fn test_get_nonce_first_time() {
        let mut mock_client = MockAcmeClientInterface::new();

        mock_client.expect_send().returning(|_| {
            let resp = hyper::Response::builder()
                .status(200)
                .header("replay-nonce", "1234567890")
                .body(Body::empty())
                .unwrap();
            Ok(resp)
        });

        let test_directory = get_test_directory(mock_client, None);
   
        let nonce = test_directory.get_nonce().await.unwrap();

        assert_eq!(nonce, "1234567890");
    }

    #[tokio::test]
    async fn test_get_nonce_exists() {
        let mut mock_client = MockAcmeClientInterface::new();

        mock_client.expect_send().times(0);

        let test_directory = get_test_directory(mock_client, Some(String::from("987654321")));
   
        let nonce = test_directory.get_nonce().await.unwrap();

        assert_eq!(nonce, "987654321");
    }
}
