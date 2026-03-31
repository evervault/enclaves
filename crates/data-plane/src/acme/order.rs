use crate::acme::account::Account;
use crate::acme::error::*;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509Name;
use openssl::x509::X509Req;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::acme::helpers::*;
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;

use super::client::AcmeClientInterface;
use super::directory::Directory;
use super::provider::Provider;

#[derive(Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl OrderStatus {
    pub fn is_done(&self) -> bool {
        matches!(self, OrderStatus::Valid | OrderStatus::Invalid)
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, OrderStatus::Pending)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Identifier {
    pub r#type: String,
    pub value: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Order<T: AcmeClientInterface> {
    #[serde(skip)]
    pub account: Option<Arc<Account<T>>>,
    #[serde(skip)]
    pub url: String,
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub error: Option<AcmeServerError>,
    #[serde(rename = "authorizations")]
    pub authorization_urls: Vec<String>,
    #[serde(rename = "finalize")]
    pub finalize_url: String,
    #[serde(rename = "certificate")]
    pub certificate_url: Option<String>,
}

/// A builder used to create a new [`Order`].
#[derive(Debug)]
pub struct OrderBuilder<T: AcmeClientInterface> {
    account: Arc<Account<T>>,
    identifiers: Vec<Identifier>,
}

impl<T: AcmeClientInterface> OrderBuilder<T> {
    pub fn new(account: Arc<Account<T>>) -> Self {
        OrderBuilder {
            account,
            identifiers: vec![],
        }
    }

    fn get_directory(&self) -> Result<Arc<Directory<T>>, AcmeError> {
        self.account
            .directory
            .clone()
            .ok_or(AcmeError::FieldNotFound("directory".into()))
    }

    pub fn set_identifiers(&mut self, identifiers: Vec<Identifier>) -> &mut Self {
        self.identifiers = identifiers;
        self
    }

    pub fn add_dns_identifier(&mut self, fqdn: String) -> &mut Self {
        self.identifiers.push(Identifier {
            r#type: "dns".to_string(),
            value: fqdn,
        });
        self
    }

    pub async fn build(&mut self, provider: Provider) -> Result<Order<T>, AcmeError> {
        let directory = self.get_directory()?;

        let response = directory
            .authenticated_request(
                &directory.new_order_url,
                "POST",
                Some(json!({
                "identifiers": self.identifiers,
                })),
                &Some(self.account.id.clone()),
                provider,
            )
            .await?;

        let headers = response.headers().clone();
        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;
        let mut order: Order<_> = serde_json::from_str(body_str)?;

        let order_url = headers
            .get(hyper::header::LOCATION)
            .ok_or(AcmeError::General(String::from(
                "No location header in newOrder response",
            )))?
            .to_str()?
            .to_string();

        order.account = Some(self.account.clone());
        order.url = order_url;

        Ok(order)
    }
}

fn gen_csr(
    key_pair: &PKey<openssl::pkey::Private>,
    domains: Vec<String>,
) -> Result<X509Req, AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::CsrError(String::from(
            "CSR validation error: At least one domain name needs to be supplied",
        )));
    }

    let mut builder = X509Req::builder()?;
    let name = {
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", &domains[0])?;
        name.build()
    };
    builder.set_subject_name(&name)?;

    let san_extension = {
        let mut san = SubjectAlternativeName::new();
        for domain in domains.iter() {
            san.dns(domain);
        }
        san.build(&builder.x509v3_context(None))?
    };
    let mut stack = Stack::new()?;
    stack.push(san_extension)?;
    builder.add_extensions(&stack)?;

    builder.set_pubkey(key_pair)?;
    builder.sign(key_pair, MessageDigest::sha256())?;

    Ok(builder.build())
}

impl<T: AcmeClientInterface> Order<T> {
    pub async fn finalize(&self, pkey: PKey<Private>) -> Result<Order<T>, AcmeError> {
        let csr = gen_csr(
            &pkey,
            self.identifiers
                .iter()
                .map(|f| f.value.clone())
                .collect::<Vec<_>>(),
        )?;

        let csr_b64 = b64(&csr.to_der()?);
        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &self.finalize_url,
                "POST",
                Some(json!({ "csr": csr_b64 })),
                &Some(account.id.clone()),
                account.provider.clone().unwrap_or(Provider::LetsEncrypt),
            )
            .await?;

        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;
        let mut order: Order<_> = serde_json::from_str(body_str)?;

        order.account = Some(account.clone());
        order.url.clone_from(&self.url);
        Ok(order)
    }

    pub async fn certificate(&self) -> Result<Option<Vec<X509>>, AcmeError> {
        let certificate_url = match self.certificate_url.clone() {
            Some(certificate_url) => certificate_url,
            None => return Ok(None),
        };

        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &certificate_url,
                "POST",
                None,
                &Some(account.id.clone()),
                account.provider.clone().unwrap_or(Provider::LetsEncrypt),
            )
            .await?;

        let body_bytes = hyper::body::to_bytes(response.into_body()).await?;

        Ok(Some(X509::stack_from_pem(&body_bytes)?))
    }

    pub async fn poll(&self) -> Result<Order<T>, AcmeError> {
        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &self.url,
                "POST",
                None,
                &Some(account.id.clone()),
                account.provider.clone().unwrap_or(Provider::LetsEncrypt),
            )
            .await?;

        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;

        let mut order: Order<_> = serde_json::from_str(body_str)?;

        order.account = Some(account.clone());
        order.url.clone_from(&self.url);
        Ok(order)
    }

    pub async fn wait_ready(
        self,
        poll_interval: Duration,
        attempts: usize,
    ) -> Result<Order<T>, AcmeError> {
        let mut order = self;

        let mut i: usize = 0;

        while order.status.is_pending() {
            if i >= attempts {
                return Err(AcmeError::General(
                    "Max attempts reached for polling order.".into(),
                ));
            }
            tokio::time::sleep(poll_interval).await;
            order = order.poll().await?;
            i += 1;
        }

        Ok(order)
    }

    pub async fn wait_done(
        self,
        poll_interval: Duration,
        attempts: usize,
    ) -> Result<Order<T>, AcmeError> {
        let mut order = self;

        let mut i: usize = 0;

        while !order.status.is_done() {
            if i >= attempts {
                return Err(AcmeError::General(
                    "Max attempts reached for polling order.".to_string(),
                ));
            }
            tokio::time::sleep(poll_interval).await;
            order = order.poll().await?;
            i += 1;
        }

        Ok(order)
    }
}
