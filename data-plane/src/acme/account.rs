use crate::acme::directory::Directory;
use crate::acme::error::*;

use openssl::pkey::PKey;
use openssl::pkey::Private;
use serde::Deserialize;
use serde_json::json;
use shared::acme::helpers::*;
use shared::server::config_server::requests::SignatureType;
use std::str::from_utf8;
use std::sync::Arc;

use super::client::AcmeClientInterface;

#[derive(Deserialize, Eq, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account<T: AcmeClientInterface> {
    #[serde(skip)]
    pub directory: Option<Arc<Directory<T>>>,
    #[serde(skip)]
    pub private_key: Option<PKey<Private>>,
    #[serde(skip)]
    pub id: String,
    pub status: AccountStatus,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct AccountBuilder<T: AcmeClientInterface> {
    directory: Arc<Directory<T>>,
    private_key: Option<PKey<Private>>,
    eab_required: bool,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
}

impl<T: AcmeClientInterface> AccountBuilder<T> {
    pub fn new(directory: Arc<Directory<T>>) -> Self {
        AccountBuilder {
            directory,
            private_key: None,
            eab_required: true,
            contact: None,
            terms_of_service_agreed: None,
            only_return_existing: None,
        }
    }

    pub fn private_key(&mut self, private_key: PKey<Private>) -> &mut Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn contact(&mut self, contact: Vec<String>) -> &mut Self {
        self.contact = Some(contact);
        self
    }

    pub fn terms_of_service_agreed(&mut self, terms_of_service_agreed: bool) -> &mut Self {
        self.terms_of_service_agreed = Some(terms_of_service_agreed);
        self
    }

    pub fn only_return_existing(&mut self, only_return_existing: bool) -> &mut Self {
        self.only_return_existing = Some(only_return_existing);
        self
    }

    pub async fn build(&mut self) -> Result<Arc<Account<T>>, AcmeError> {
        let private_key = if let Some(private_key) = self.private_key.clone() {
            private_key
        } else {
            gen_ec_private_key()?
        };

        let url = self.directory.new_account_url.clone();
        let config_client = self.directory.config_client.clone();

        let external_account_binding = if self.eab_required {
            let jwk_response = config_client.jwk().await?;
            let payload = serde_json::to_string(&jwk_response)?;

            let jws = config_client
                .jws(
                    SignatureType::HMAC,
                    url.clone(),
                    None,
                    payload,
                    None, //Injected in control plane
                )
                .await?;

            Some(jws)
        } else {
            None
        };

        let res = self
            .directory
            .authenticated_request(
                &url,
                "POST",
                Some(json!({
                  "contact": self.contact,
                  "termsOfServiceAgreed": self.terms_of_service_agreed,
                  "onlyReturnExisting": self.only_return_existing,
                  "externalAccountBinding": external_account_binding,
                })),
                &None,
            )
            .await?;

        let headers = res.headers().clone();
        let resp_bytes = hyper::body::to_bytes(res.into_body()).await?;
        let body_str = from_utf8(&resp_bytes).expect("Body was not valid UTF-8");
        println!("Account Response: {}", body_str);
        let mut account: Account<_> =
            serde_json::from_str(body_str).expect("Failed to deserialize Account");

        let account_id = headers
            .get(hyper::header::LOCATION)
            .ok_or(AcmeError::General(String::from(
                "No location header in newAccount request",
            )))?
            .to_str()?
            .to_string();

        account.directory = Some(self.directory.clone());
        account.private_key = Some(private_key);
        account.id = account_id;
        Ok(Arc::new(account))
    }
}

impl<T: AcmeClientInterface> Account<T> {
    pub fn private_key(&self) -> Result<PKey<Private>, AcmeError> {
        self.private_key.clone().ok_or(AcmeError::General(
            "No private key found for account".to_string(),
        ))
    }
}
