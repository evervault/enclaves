use std::fs;

use configuration::should_forward_proxy_protocol;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

#[cfg(test)]
pub mod mocks;

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
pub mod utils;
#[cfg(feature = "network_egress")]
use shared::server::egress::{get_egress_ports_from_env, EgressConfig};
#[cfg(feature = "tls_termination")]
pub mod server;

use shared::server::config_server::requests::GetCertResponseDataPlane;
use thiserror::Error;

static CAGE_CONTEXT: OnceCell<CageContext> = OnceCell::new();
static FEATURE_CONTEXT: OnceCell<FeatureContext> = OnceCell::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CageContext {
    team_uuid: String,
    app_uuid: String,
    cage_uuid: String,
    cage_name: String,
    healthcheck: Option<String>,
}

#[derive(Error, Debug)]
pub enum CageContextError {
    #[error("Cage context has not yet been initialized")]
    ContextNotInitialized,
}

impl CageContext {
    fn get() -> Result<CageContext, CageContextError> {
        CAGE_CONTEXT
            .get()
            .map(|context| context.to_owned())
            .ok_or(CageContextError::ContextNotInitialized)
    }

    fn set(ctx: CageContext) {
        CAGE_CONTEXT.get_or_init(|| ctx);
    }

    pub fn new(
        team_uuid: String,
        app_uuid: String,
        cage_uuid: String,
        cage_name: String,
        healthcheck: Option<String>,
    ) -> Self {
        Self {
            cage_uuid,
            app_uuid,
            team_uuid,
            cage_name,
            healthcheck,
        }
    }

    pub fn cage_uuid(&self) -> &str {
        &self.cage_uuid
    }

    pub fn cage_name(&self) -> &str {
        &self.cage_name
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
        format!("{}.{}.cages.evervault.dev", &self.cage_name, &self.app_uuid)
    }

    #[cfg(staging)]
    pub fn get_hyphenated_cert_name(&self) -> String {
        let hyphenated_app_uuid = self.app_uuid.clone().replace('_', "-");
        log::debug!("hyphenated_app_uuid: {:?}", hyphenated_app_uuid);
        format!(
            "{}.{}.cages.evervault.dev",
            &self.cage_name, hyphenated_app_uuid
        )
    }

    #[cfg(not(staging))]
    pub fn get_cert_name(&self) -> String {
        format!("{}.{}.cages.evervault.com", &self.cage_name, &self.app_uuid)
    }

    #[cfg(not(staging))]
    pub fn get_hyphenated_cert_name(&self) -> String {
        let hyphenated_app_uuid = self.app_uuid.clone().replace('_', "-");
        format!(
            "{}.{}.cages.evervault.com",
            &self.cage_name, hyphenated_app_uuid
        )
    }

    #[cfg(not(staging))]
    pub fn get_trusted_cert_name(&self) -> String {
        format!(
            "{}.{}.cage.evervault.com",
            &self.cage_name,
            &self.hyphenated_app_uuid()
        )
    }

    #[cfg(staging)]
    pub fn get_trusted_cert_name(&self) -> String {
        format!(
            "{}.{}.cage.evervault.dev",
            &self.cage_name,
            &self.hyphenated_app_uuid()
        )
    }

    pub fn get_cert_names(&self) -> Vec<String> {
        let underscored_name = self.get_cert_name();
        let hyphenated_name = self.get_hyphenated_cert_name();
        vec![underscored_name, hyphenated_name]
    }
}

impl From<GetCertResponseDataPlane> for CageContext {
    fn from(cert_response: GetCertResponseDataPlane) -> Self {
        CageContext::new(
            cert_response.context.team_uuid,
            cert_response.context.app_uuid,
            cert_response.context.cage_uuid,
            cert_response.context.cage_name,
            cert_response.healthcheck,
        )
    }
}

impl FeatureContext {
    pub fn set() {
        match Self::read_dataplane_context() {
            Some(context) => FEATURE_CONTEXT.get_or_init(|| context),
            None => FEATURE_CONTEXT.get_or_init(Self::from_env),
        };
    }
    pub fn get() -> FeatureContext {
        FEATURE_CONTEXT
            .get()
            .expect("Couldn't get feature context")
            .clone()
    }

    // Need to support from env for older versions of CLI - Remove after beta
    fn from_env() -> FeatureContext {
        let api_key_auth = std::env::var("EV_API_KEY_AUTH")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        let trx_logging_enabled = std::env::var("EV_TRX_LOGGING_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);
        FeatureContext {
            api_key_auth,
            trx_logging_enabled,
            forward_proxy_protocol: should_forward_proxy_protocol(),
            trusted_headers: vec![],
            #[cfg(feature = "network_egress")]
            egress: EgressConfig {
                ports: get_egress_ports_from_env(),
                allow_list: shared::server::egress::get_egress_allow_list_from_env(),
            },
        }
    }

    fn read_dataplane_context() -> Option<FeatureContext> {
        let mut feature_context: FeatureContext = fs::read_to_string("/etc/dataplane-config.json")
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())?;
        // map trusted headers to lowercase
        feature_context.trusted_headers = feature_context
            .trusted_headers
            .iter()
            .map(|header| header.to_lowercase())
            .collect();
        Some(feature_context)
    }
}

#[derive(Clone, Deserialize)]
pub struct FeatureContext {
    pub api_key_auth: bool,
    pub trx_logging_enabled: bool,
    #[serde(default)]
    pub forward_proxy_protocol: bool,
    #[serde(default)]
    pub trusted_headers: Vec<String>,
    #[cfg(feature = "network_egress")]
    pub egress: EgressConfig,
}

#[cfg(test)]
mod test {
    use super::FeatureContext;
    #[cfg(not(feature = "network_egress"))]
    #[test]
    fn test_config_deserialization_without_proxy_protocol() {
        let raw_feature_context = r#"{ "api_key_auth": true, "trx_logging_enabled": false }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, false);
    }

    #[cfg(feature = "network_egress")]
    #[test]
    fn test_config_deserialization_with_egress() {
        let raw_feature_context = r#"{ "api_key_auth": true, "trx_logging_enabled": false, "forward_proxy_protocol": true, "egress": { "ports": "443,8080", "allow_list": "*.stripe.com" } }"#;
        let parsed = serde_json::from_str(raw_feature_context);
        assert!(parsed.is_ok());
        let feature_context: FeatureContext = parsed.unwrap();
        assert_eq!(feature_context.api_key_auth, true);
        assert_eq!(feature_context.trx_logging_enabled, false);
        assert_eq!(feature_context.forward_proxy_protocol, true);
        assert_eq!(feature_context.egress.ports, vec![443, 8080]);
        assert_eq!(
            feature_context.egress.allow_list.wildcard,
            vec![".stripe.com".to_string()]
        );
    }
}
