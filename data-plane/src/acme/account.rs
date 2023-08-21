use crate::acme::directory::Directory;
use crate::acme::error::*;
use crate::acme::helpers::*;
use crate::acme::jws::jws;
use crate::acme::jws::Jwk;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use serde::Deserialize;
use serde_json::json;
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

#[derive(Debug, Clone)]
pub struct ExternalAccountBinding {
    key_id: String,
    //HMAC key
    private_key: PKey<Private>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Account<T: AcmeClientInterface> {
    #[serde(skip)]
    pub directory: Option<Arc<Directory<T>>>,
    #[serde(skip)]
    pub private_key: Option<PKey<Private>>,
    #[serde(skip)]
    pub eab_config: Option<ExternalAccountBinding>,
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
    eab_config: Option<ExternalAccountBinding>,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
}

impl<T: AcmeClientInterface + Default> AccountBuilder<T> {
    pub fn new(directory: Arc<Directory<T>>) -> Self {
        AccountBuilder {
            directory,
            private_key: None,
            eab_config: None,
            contact: None,
            terms_of_service_agreed: None,
            only_return_existing: None,
        }
    }

    pub fn private_key(&mut self, private_key: PKey<Private>) -> &mut Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn external_account_binding(
        &mut self,
        key_id: String,
        private_key: PKey<Private>,
    ) -> &mut Self {
        self.eab_config = Some(ExternalAccountBinding {
            key_id,
            private_key,
        });
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

        let external_account_binding = if let Some(eab_config) = &self.eab_config {
            let payload = serde_json::to_string(&Jwk::new(&private_key)?)?;

            Some(jws(
                &url,
                None,
                &payload,
                &eab_config.private_key,
                Some(eab_config.key_id.clone()),
            )?)
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
                &private_key.clone(),
                &None,
            )
            .await?;

        let headers = res.headers().clone();
        let resp_bytes = hyper::body::to_bytes(res.into_body()).await?;
        let body_str = from_utf8(&resp_bytes).expect("Body was not valid UTF-8");
        let mut account: Account<_> =
            serde_json::from_str(body_str).expect("Failed to deserialize Directory");

        let account_id = headers
            .get(hyper::header::LOCATION)
            .ok_or(AcmeError::General(String::from(
                "No location header in newAccount request",
            )))?
            .to_str()?
            .to_string();

        account.directory = Some(self.directory.clone());
        account.private_key = Some(private_key);
        account.eab_config = self.eab_config.clone();
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
