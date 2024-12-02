use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{fs, future::Future, task::ready};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
pub mod mocks;

#[cfg(feature = "tls_termination")]
pub mod acme;

pub mod base_tls_client;
pub mod cache;
pub mod cert_provisioner_client;
pub mod config_client;
pub mod configuration;
pub mod connection;
pub mod crypto;
pub mod dns;
pub mod e3client;
pub mod env;
pub mod error;
pub mod health;
pub mod stats;
pub mod stats_client;
pub mod time;
pub mod utils;
#[cfg(feature = "network_egress")]
use shared::server::egress::EgressConfig;
#[cfg(feature = "tls_termination")]
pub mod server;

use shared::server::config_server::requests::ProvisionerContext;
use thiserror::Error;

static ENCLAVE_CONTEXT: OnceCell<EnclaveContext> = OnceCell::new();
static FEATURE_CONTEXT: OnceCell<FeatureContext> = OnceCell::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnclaveContext {
    team_uuid: String,
    app_uuid: String,
    uuid: String,
    name: String,
}

#[derive(Error, Debug)]
pub enum ContextError {
    #[error("Failed to read context from file - {0}")]
    FailedToRead(#[from] std::io::Error),
    #[error("Failed to parse read context - {0}")]
    FailedToParse(#[from] serde_json::error::Error),
    #[error("Attempted to read the context in the enclave before it was set.")]
    Uninitialized,
}

impl EnclaveContext {
    fn get() -> Result<EnclaveContext, ContextError> {
        ENCLAVE_CONTEXT
            .get()
            .map(|context| context.to_owned())
            .ok_or(ContextError::Uninitialized)
    }

    fn set(ctx: EnclaveContext) {
        ENCLAVE_CONTEXT.get_or_init(|| ctx);
    }

    pub fn new(team_uuid: String, app_uuid: String, uuid: String, name: String) -> Self {
        Self {
            uuid,
            app_uuid,
            team_uuid,
            name,
        }
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn hyphenated_app_uuid(&self) -> String {
        self.app_uuid.replace('_', "-")
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }

    #[cfg(staging)]
    pub fn get_cert_name(&self) -> String {
        format!("{}.{}.cages.evervault.dev", &self.name, &self.app_uuid)
    }

    #[cfg(staging)]
    pub fn get_hyphenated_cert_name(&self) -> String {
        let hyphenated_app_uuid = self.app_uuid.clone().replace('_', "-");
        log::debug!("hyphenated_app_uuid: {:?}", hyphenated_app_uuid);
        format!("{}.{}.cages.evervault.dev", &self.name, hyphenated_app_uuid)
    }

    #[cfg(not(staging))]
    pub fn get_cert_name(&self) -> String {
        format!("{}.{}.cages.evervault.com", &self.name, &self.app_uuid)
    }

    #[cfg(not(staging))]
    pub fn get_hyphenated_cert_name(&self) -> String {
        let hyphenated_app_uuid = self.app_uuid.clone().replace('_', "-");
        format!("{}.{}.cages.evervault.com", &self.name, hyphenated_app_uuid)
    }

    pub fn get_trusted_cert_domains(&self) -> Vec<String> {
        #[cfg(not(staging))]
        let base_domains = ["cage.evervault.com", "enclave.evervault.com"];

        #[cfg(staging)]
        let base_domains = ["cage.evervault.dev", "enclave.evervault.dev"];

        base_domains
            .iter()
            .map(|domain| format!("{}.{}.{}", &self.name, &self.hyphenated_app_uuid(), domain))
            .collect()
    }

    pub fn get_cert_names(&self) -> Vec<String> {
        let underscored_name = self.get_cert_name();
        let hyphenated_name = self.get_hyphenated_cert_name();
        vec![underscored_name, hyphenated_name]
    }
}

impl From<ProvisionerContext> for EnclaveContext {
    fn from(context: ProvisionerContext) -> Self {
        EnclaveContext::new(
            context.team_uuid,
            context.app_uuid,
            context.cage_uuid,
            context.cage_name,
        )
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct FeatureContext {
    pub api_key_auth: bool,
    pub healthcheck: Option<String>,
    pub healthcheck_port: Option<u16>,
    pub healthcheck_use_tls: Option<bool>,
    pub trx_logging_enabled: bool,
    pub forward_proxy_protocol: bool,
    pub trusted_headers: Vec<String>,
    #[cfg(feature = "network_egress")]
    pub egress: EgressConfig,
}

impl FeatureContext {
    pub fn set() -> Result<(), ContextError> {
        Self::read_dataplane_context().map(|context| {
            FEATURE_CONTEXT.get_or_init(|| context);
        })
    }

    pub fn get() -> Result<FeatureContext, ContextError> {
        FEATURE_CONTEXT
            .get()
            .cloned()
            .ok_or(ContextError::Uninitialized)
    }

    fn read_dataplane_context() -> Result<FeatureContext, ContextError> {
        let feature_context_file_contents = fs::read_to_string("/etc/dataplane-config.json")?;
        let mut feature_context: FeatureContext =
            serde_json::from_str(&feature_context_file_contents)?;
        // map trusted headers to lowercase
        feature_context.trusted_headers = feature_context
            .trusted_headers
            .iter()
            .map(|header| header.to_lowercase())
            .collect();
        Ok(feature_context)
    }
}

pub enum CancellableResult<T> {
    Cancelled,
    Complete(T),
}

impl<T> CancellableResult<T> {
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    pub fn unwrap(self) -> T {
        match self {
            Self::Cancelled => panic!("unwrap called on cancelled result"),
            Self::Complete(result) => result,
        }
    }
}

/// The critical service trait is used to represent the interdepence of the critical in-Enclave services. If any critical service fails,
/// all other critical services should be cancelled to force the Enclave to be restarted. This process is managed using a cancellation token.
pub trait Critical: Future {
    fn critical(self, cancellation_token: CancellationToken) -> CriticalService<Self>
    where
        Self: Sized,
    {
        CriticalService {
            inner: self,
            cancellation_token,
        }
    }
}

impl<F: ?Sized> Critical for F where F: Future {}

#[pin_project::pin_project]
pub struct CriticalService<F: Future> {
    #[pin]
    inner: F,
    #[pin]
    cancellation_token: CancellationToken,
}

impl<F: Future> Future for CriticalService<F> {
    type Output = CancellableResult<F::Output>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let is_cancelled = this.cancellation_token.is_cancelled();
        if is_cancelled {
            return std::task::Poll::Ready(CancellableResult::Cancelled);
        }

        let result = ready!(this.inner.poll(cx));
        this.cancellation_token.cancel();
        std::task::Poll::Ready(CancellableResult::Complete(result))
    }
}

#[cfg(test)]
mod test {
    use super::{Critical, FeatureContext};
    use tokio_util::sync::CancellationToken;
    #[cfg(not(feature = "network_egress"))]
    #[test]
    fn test_config_deserialization_without_proxy_protocol() {
        let raw_feature_context = r#"{ "api_key_auth": true, "trx_logging_enabled": false, "forward_proxy_protocol": false, "trusted_headers": [] }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, false);
        assert!(feature_context.healthcheck.is_none());
    }

    #[cfg(not(feature = "network_egress"))]
    #[test]
    fn test_config_deserialization_without_proxy_protocol_and_healthcheck() {
        let raw_feature_context = r#"{ "api_key_auth": true, "healthcheck": "/health", "trx_logging_enabled": false, "forward_proxy_protocol": false, "trusted_headers": [] }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, false);
        assert_eq!(feature_context.healthcheck, Some("/health".into()));
    }

    #[cfg(feature = "network_egress")]
    #[test]
    fn test_config_deserialization_with_egress() {
        let raw_feature_context = r#"{ "api_key_auth": true, "trx_logging_enabled": false, "forward_proxy_protocol": true, "trusted_headers": ["X-Error-Code"], "egress": { "ports": "443,8080", "allow_list": "*.stripe.com" } }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, true);
        assert_eq!(
            feature_context.trusted_headers,
            vec!["X-Error-Code".to_string()]
        );
        assert!(feature_context.healthcheck.is_none());
        assert_eq!(
            feature_context.egress.allow_list.wildcard,
            vec![".stripe.com".to_string()]
        );
    }

    #[cfg(feature = "network_egress")]
    #[test]
    fn test_config_deserialization_with_egress_and_healthcheck() {
        let raw_feature_context = r#"{ "api_key_auth": true, "healthcheck": "/health", "trx_logging_enabled": false, "forward_proxy_protocol": true, "trusted_headers": [], "egress": { "ports": "443,8080", "allow_list": "*.stripe.com" } }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, true);
        let trusted_headers: Vec<String> = Vec::new();
        assert_eq!(feature_context.trusted_headers, trusted_headers);
        assert_eq!(
            feature_context.egress.allow_list.wildcard,
            vec![".stripe.com".to_string()]
        );
        assert_eq!(feature_context.healthcheck, Some("/health".into()));
    }

    #[tokio::test]
    async fn test_critical_service_exits_tasks_as_expected() {
        let cancellation_token = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        let fut1 = async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            sender.send(1).unwrap();
        }
        .critical(cancellation_token.child_token());

        let fut2 = async move {
            cancellation_token.cancel();
            2
        };

        let (res1, res2) = tokio::join!(fut1, fut2);
        assert!(res1.is_cancelled());
        assert_eq!(res2, 2);
        // Assert that we forced the exit of the async task without it sending a message
        let msg = receiver.try_recv();
        assert!(msg.is_err());
    }

    #[tokio::test]
    async fn test_critical_services_are_made_interdependent_on_each_other() {
        let cancellation_token = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let sender1 = sender.clone();

        let fut1 = async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            sender1.send(1).await.unwrap();
        }
        .critical(cancellation_token.clone());

        let fut2 = async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            sender.send(2).await.unwrap();
        }
        .critical(cancellation_token.clone());

        let fut3 = async move { Ok(()) as Result<(), ()> }.critical(cancellation_token.clone());

        let (res1, res2, res3) = tokio::join!(fut1, fut2, fut3);
        assert!(cancellation_token.is_cancelled());
        assert_eq!(res3.unwrap(), Ok(()));
        assert!(res1.is_cancelled());
        assert!(res2.is_cancelled());
        // Assert that we forced the exit of the async task without it sending a message
        let msg = receiver.try_recv();
        assert!(msg.is_err());
    }
}
