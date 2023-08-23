use crate::acme::account::Account;
use crate::acme::error::*;
use crate::acme::helpers::*;
use crate::acme::jws::Jwk;
use crate::acme::order::Order;
use crate::acme::order::*;
use openssl::hash::hash;
use openssl::hash::MessageDigest;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde_json::json;
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;

use super::client::AcmeClientInterface;
use super::directory::Directory;
use super::jws::JwkThumb;

#[derive(Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Authorization<T: AcmeClientInterface> {
    #[serde(skip)]
    pub account: Option<Arc<Account<T>>>,
    #[serde(skip)]
    pub url: String,
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub expires: Option<String>,
    #[serde(deserialize_with = "skip_account")]
    pub challenges: Vec<Challenge<T>>,
    pub wildcard: Option<bool>,
}

#[derive(Deserialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Challenge<T: AcmeClientInterface> {
    #[serde(skip_serializing, skip_deserializing)]
    pub account: Option<Arc<Account<T>>>,
    pub r#type: String,
    pub url: String,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub error: Option<AcmeServerError>,
    pub token: Option<String>,
}

// Need this as the derive macro doesn't support nested generics being skipped eg: Challenge skips deserializing Account<T> but Authorization
// doesn't recoginize that Challenge<T> skips the use of T and looks to be able to Deserialise Challenge<T: AcmeClientInterface>
fn skip_account<'de, D, T: AcmeClientInterface>(
    deserializer: D,
) -> Result<Vec<Challenge<T>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct IntermediateChallenge {
        r#type: String,
        url: String,
        status: ChallengeStatus,
        validated: Option<String>,
        error: Option<AcmeServerError>,
        token: Option<String>,
    }

    struct ChallengesVisitor<T: AcmeClientInterface>(std::marker::PhantomData<T>);

    impl<'de, T: AcmeClientInterface> Visitor<'de> for ChallengesVisitor<T> {
        type Value = Vec<Challenge<T>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of challenges")
        }

        fn visit_seq<S: serde::de::SeqAccess<'de>>(
            self,
            mut seq: S,
        ) -> Result<Self::Value, S::Error> {
            let mut challenges = Vec::new();
            while let Some(challenge) = seq.next_element::<IntermediateChallenge>()? {
                challenges.push(Challenge {
                    account: None,
                    r#type: challenge.r#type,
                    url: challenge.url,
                    status: challenge.status,
                    validated: challenge.validated,
                    error: challenge.error,
                    token: challenge.token,
                });
            }
            Ok(challenges)
        }
    }

    deserializer.deserialize_seq(ChallengesVisitor(std::marker::PhantomData))
}

impl<T: AcmeClientInterface> Order<T> {
    pub fn get_account_and_directory(&self) -> Result<AccountAndDirectory<T>, AcmeError> {
        let account = self
            .account
            .clone()
            .ok_or(AcmeError::FieldNotFound("account".into()))?;
        let directory = account
            .directory
            .clone()
            .ok_or(AcmeError::FieldNotFound("directory".into()))?;

        Ok((account, directory))
    }

    pub async fn authorizations(&self) -> Result<Vec<Authorization<T>>, AcmeError> {
        let (account, directory) = self.get_account_and_directory()?;

        let mut authorizations = vec![];

        for authorization_url in self.authorization_urls.clone() {
            let response = directory
                .authenticated_request(
                    &authorization_url,
                    "POST",
                    None,
                    &account
                        .private_key
                        .clone()
                        .ok_or(AcmeError::FieldNotFound("private_key".into()))?,
                    &Some(account.id.clone()),
                )
                .await?;

            let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
            let body_str = from_utf8(&resp_bytes)?;

            let mut authorization: Authorization<_> = serde_json::from_str(body_str)?;

            authorization.account = Some(account.clone());
            authorization.url = authorization_url;
            for challenge in &mut authorization.challenges {
                challenge.account = Some(account.clone())
            }
            authorizations.push(authorization)
        }

        Ok(authorizations)
    }
}

type AccountAndDirectory<T> = (Arc<Account<T>>, Arc<Directory<T>>);

impl<T: AcmeClientInterface> Authorization<T> {
    pub fn get_account_and_directory(&self) -> Result<AccountAndDirectory<T>, AcmeError> {
        let account = self
            .account
            .clone()
            .ok_or(AcmeError::FieldNotFound("account".into()))?;
        let directory = account
            .directory
            .clone()
            .ok_or(AcmeError::FieldNotFound("directory".into()))?;

        Ok((account, directory))
    }

    pub fn get_challenge(&self, r#type: &str) -> Option<&Challenge<T>> {
        self.challenges
            .iter()
            .find(|&challenge| challenge.r#type == r#type)
    }

    pub async fn poll(self) -> Result<Authorization<T>, AcmeError> {
        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &self.url,
                "POST",
                None,
                &account
                    .private_key
                    .clone()
                    .ok_or(AcmeError::FieldNotFound("private_key".into()))?,
                &Some(account.id.clone()),
            )
            .await?;

        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;
        let mut authorization: Authorization<T> = serde_json::from_str(body_str)?;

        authorization.url = self.url.clone();
        authorization.account = Some(account.clone());

        Ok(authorization)
    }

    pub async fn wait_done(
        self,
        poll_interval: Duration,
        attempts: usize,
    ) -> Result<Authorization<T>, AcmeError> {
        let mut authorization = self;

        let mut i: usize = 0;

        while authorization.status == AuthorizationStatus::Pending {
            println!("[ATTEMPT {}] - Waiting for authorization to complete", i);
            if i >= attempts {
                return Err(AcmeError::General(
                    "Max attempts reached for checking authorization is complete".to_string(),
                ));
            }

            tokio::time::sleep(poll_interval).await;
            authorization = authorization.poll().await?;
            i += 1;
        }

        Ok(authorization)
    }
}

impl<T: AcmeClientInterface> Challenge<T> {
    pub fn get_account_and_directory(&self) -> Result<AccountAndDirectory<T>, AcmeError> {
        let account = self
            .account
            .clone()
            .ok_or(AcmeError::FieldNotFound("account".into()))?;
        let directory = account
            .directory
            .clone()
            .ok_or(AcmeError::FieldNotFound("directory".into()))?;

        Ok((account, directory))
    }

    pub fn key_authorization(&self) -> Result<Option<String>, AcmeError> {
        if let Some(token) = self.token.clone() {
            let (account, _) = self.get_account_and_directory()?;

            let jwk = &Jwk::new(
                &account
                    .private_key
                    .clone()
                    .ok_or(AcmeError::FieldNotFound("private_key".into()))?,
            )?;

            let jwk_thumb: JwkThumb = jwk.into();

            let key_authorization = format!(
                "{}.{}",
                token,
                b64(&hash(
                    MessageDigest::sha256(),
                    &serde_json::to_string(&jwk_thumb)?.into_bytes()
                )?)
            );

            Ok(Some(key_authorization))
        } else {
            Ok(None)
        }
    }

    pub async fn validate(&self) -> Result<Challenge<T>, AcmeError> {
        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &self.url,
                "POST",
                Some(json!({})),
                &account
                    .private_key
                    .clone()
                    .ok_or(AcmeError::FieldNotFound("private_key".into()))?,
                &Some(account.id.clone()),
            )
            .await?;

        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;
        let mut challenge: Challenge<_> = serde_json::from_str(body_str)?;

        challenge.account = Some(account.clone());

        Ok(challenge)
    }

    pub async fn poll(&self) -> Result<Challenge<T>, AcmeError> {
        let (account, directory) = self.get_account_and_directory()?;

        let response = directory
            .authenticated_request(
                &self.url,
                "POST",
                Some(json!("")),
                &account
                    .private_key
                    .clone()
                    .ok_or(AcmeError::FieldNotFound("private_key".into()))?,
                &Some(account.id.clone()),
            )
            .await?;

        let resp_bytes = hyper::body::to_bytes(response.into_body()).await?;
        let body_str = from_utf8(&resp_bytes)?;

        let mut challenge: Challenge<_> = serde_json::from_str(body_str)?;

        challenge.account = Some(account.clone());
        Ok(challenge)
    }

    pub async fn wait_done(
        self,
        poll_interval: Duration,
        attempts: usize,
    ) -> Result<Challenge<T>, AcmeError> {
        let mut challenge = self;

        let mut i: usize = 0;

        while challenge.status == ChallengeStatus::Pending
            || challenge.status == ChallengeStatus::Processing
        {
            if i >= attempts {
                return Err(AcmeError::General(
                    "Max attempts polling challenge exceeded".to_string(),
                ));
            }

            tokio::time::sleep(poll_interval).await;
            challenge = challenge.poll().await?;
            i += 1;
        }

        Ok(challenge)
    }
}
