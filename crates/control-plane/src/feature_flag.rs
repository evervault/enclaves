use crate::configuration::EnclaveContext;
use hyper::client::HttpConnector;
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
use launchdarkly_server_sdk::{
    Client, ConfigBuilder, EventProcessorBuilder, ServiceEndpointsBuilder,
    StreamingDataSourceBuilder,
};
pub use launchdarkly_server_sdk::{Context, ContextBuilder};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdError {
    #[error("No Launch Darkly API key found in the environment")]
    NoApiKeyFoundInEnvironment,
    #[error("Launch Darkly config is invalid, likely an invalid api key: {0}")]
    InvalidLdConfig(String),
    #[error("Failed to initialize the Launch Darkly SDK")]
    InitializationFailed,
    #[error("Failed to construct context: {0}")]
    ContextBuild(String),
}

#[cfg_attr(test, mockall::automock)]
pub trait FeatureFlagProvider: std::fmt::Debug + Send + Sync {
    fn string_feature_flag_with_context(
        &self,
        flag: &str,
        context: &Context,
        default: String,
    ) -> Result<String, LdError>;

    fn bool_feature_flag_with_context(
        &self,
        flag: &str,
        context: &Context,
        default: bool,
    ) -> Result<bool, LdError>;

    fn shutdown(&self);
}

#[derive(Clone)]
pub struct LaunchDarklyClient {
    inner: Arc<Client>,
}

impl std::fmt::Debug for LaunchDarklyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchDarklyClient")
    }
}

impl LaunchDarklyClient {
    pub async fn try_new() -> Result<Self, LdError> {
        let client = initialize_ld_client()?;
        let arc_client = Arc::new(client);
        let init_timeout = std::time::Duration::from_secs(3);
        let initialised = arc_client
            .wait_for_initialization(init_timeout)
            .await
            .unwrap_or(false);
        if !initialised {
            return Err(LdError::InitializationFailed);
        }
        Ok(Self { inner: arc_client })
    }
}

impl FeatureFlagProvider for LaunchDarklyClient {
    fn string_feature_flag_with_context(
        &self,
        flag: &str,
        context: &Context,
        default: String,
    ) -> Result<String, LdError> {
        Ok(self.inner.str_variation(context, flag, default))
    }

    fn bool_feature_flag_with_context(
        &self,
        flag: &str,
        context: &Context,
        default: bool,
    ) -> Result<bool, LdError> {
        Ok(self.inner.bool_variation(context, flag, default))
    }

    fn shutdown(&self) {
        self.inner.close();
    }
}

#[derive(Debug, Default, Clone)]
pub struct NoopFeatureFlagProvider;

impl FeatureFlagProvider for NoopFeatureFlagProvider {
    fn string_feature_flag_with_context(
        &self,
        _flag: &str,
        _context: &Context,
        default: String,
    ) -> Result<String, LdError> {
        Ok(default)
    }

    fn bool_feature_flag_with_context(
        &self,
        _flag: &str,
        _context: &Context,
        default: bool,
    ) -> Result<bool, LdError> {
        Ok(default)
    }

    fn shutdown(&self) {}
}

impl From<launchdarkly_server_sdk::ConfigBuildError> for LdError {
    fn from(error: launchdarkly_server_sdk::ConfigBuildError) -> Self {
        match error {
            launchdarkly_server_sdk::ConfigBuildError::InvalidConfig(s) => {
                LdError::InvalidLdConfig(s)
            }
            _ => LdError::InvalidLdConfig("Unknown build error".to_string()),
        }
    }
}

impl From<launchdarkly_server_sdk::BuildError> for LdError {
    fn from(error: launchdarkly_server_sdk::BuildError) -> Self {
        match error {
            launchdarkly_server_sdk::BuildError::InvalidConfig(s) => LdError::InvalidLdConfig(s),
            _ => LdError::InvalidLdConfig("Unknown build error".to_string()),
        }
    }
}

impl From<http::uri::InvalidUri> for LdError {
    fn from(error: http::uri::InvalidUri) -> Self {
        LdError::InvalidLdConfig(error.to_string())
    }
}

fn initialize_ld_client() -> Result<Client, LdError> {
    let Ok(ld_sdk_key) = std::env::var("LAUNCHDARKLY_SDK_KEY") else {
        return Err(LdError::NoApiKeyFoundInEnvironment);
    };

    let ld_config = if let Ok(http_proxy) = std::env::var("HTTP_PROXY") {
        let proxy_uri = http_proxy
            .parse()
            .map_err(|e| LdError::InvalidLdConfig(format!("Invalid proxy URI: {e}")))?;
        let proxy = Proxy::new(Intercept::All, proxy_uri);
        let connector = HttpConnector::new();
        let proxy_connector = ProxyConnector::from_proxy(connector, proxy)
            .map_err(|e| LdError::InvalidLdConfig(format!("Proxy connector init: {e}")))?;
        let mut data_source_builder = StreamingDataSourceBuilder::default();
        data_source_builder.https_connector(proxy_connector.clone());
        let mut event_processor_builder = EventProcessorBuilder::default();
        event_processor_builder.https_connector(proxy_connector);
        ConfigBuilder::new(&ld_sdk_key)
            .event_processor(&event_processor_builder)
            .data_source(&data_source_builder)
            .service_endpoints(
                ServiceEndpointsBuilder::new()
                    .polling_base_url("http://sdk.launchdarkly.com")
                    .streaming_base_url("http://stream.launchdarkly.com")
                    .events_base_url("http://events.launchdarkly.com"),
            )
            .build()
    } else {
        ConfigBuilder::new(&ld_sdk_key).build()
    };

    let client = Client::build(ld_config?)?;
    client.start_with_default_executor();

    Ok(client)
}

pub fn build_enclave_context(ctx: &EnclaveContext) -> Result<Context, LdError> {
    let mut builder = ContextBuilder::new(&ctx.uuid);
    builder
        .kind("enclave")
        .set_string("app_uuid", &ctx.app_uuid)
        .set_string("team_uuid", &ctx.team_uuid)
        .set_string("enclave_name", &ctx.name)
        .set_string("enclave_version", &ctx.version);
    builder.build().map_err(LdError::ContextBuild)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ctx() -> Context {
        ContextBuilder::new("test-cage").build().unwrap()
    }

    #[test]
    fn noop_returns_default_string() {
        let p = NoopFeatureFlagProvider;
        let ctx = dummy_ctx();
        let val = p
            .string_feature_flag_with_context("any-flag", &ctx, "default-host".into())
            .unwrap();
        assert_eq!(val, "default-host");
    }

    #[test]
    fn noop_returns_default_bool() {
        let p = NoopFeatureFlagProvider;
        let ctx = dummy_ctx();
        assert!(p
            .bool_feature_flag_with_context("any-flag", &ctx, true)
            .unwrap());
        assert!(!p
            .bool_feature_flag_with_context("any-flag", &ctx, false)
            .unwrap());
    }
}
