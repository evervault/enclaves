use std::fs;

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

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

#[cfg(feature = "tls_termination")]
pub mod server;

use shared::server::config_server::requests::ProvisionerContext;
use thiserror::Error;

static CAGE_CONTEXT: OnceCell<CageContext> = OnceCell::new();
static FEATURE_CONTEXT: OnceCell<FeatureContext> = OnceCell::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CageContext {
    team_uuid: String,
    app_uuid: String,
    cage_uuid: String,
    cage_name: String,
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

    pub fn new(app_uuid: String, team_uuid: String, cage_uuid: String, cage_name: String) -> Self {
        Self {
            cage_uuid,
            app_uuid,
            team_uuid,
            cage_name,
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

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }

    #[cfg(staging)]
    pub fn get_cert_name(&self) -> String {
        format!("{}.{}.cages.evervault.dev", &self.cage_name, &self.app_uuid)
    }

    #[cfg(not(staging))]
    pub fn get_cert_name(&self) -> String {
        format!("{}.{}.cages.evervault.com", &self.cage_name, &self.app_uuid)
    }
}

impl From<ProvisionerContext> for CageContext {
    fn from(context: ProvisionerContext) -> Self {
        CageContext::new(
            context.team_uuid,
            context.app_uuid,
            context.cage_uuid,
            context.cage_name,
        )
    }
}

impl FeatureContext {
    pub fn set() {
        match read_dataplane_context() {
            Some(context) => FEATURE_CONTEXT.get_or_init(|| context),
            None => {
                let api_key_auth = std::env::var("EV_API_KEY_AUTH")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true);
                let trx_logging_enabled = std::env::var("EV_TRX_LOGGING_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true);
                let dataplane_context = FeatureContext {
                    api_key_auth,
                    trx_logging_enabled,
                    egress: None,
                };
                FEATURE_CONTEXT.get_or_init(|| dataplane_context)
            }
        };
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureContext {
    #[serde(rename = "api_key_auth")]
    api_key_auth: bool,
    trx_logging_enabled: bool,
    egress: Option<EgressContext>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct EgressContext {
    ports: String,
    allow_list: bool,
}

fn read_dataplane_context() -> Option<FeatureContext> {
    fs::read_to_string("/etc/dataplane-config.json")
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
}
