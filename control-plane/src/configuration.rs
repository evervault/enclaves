use std::str::FromStr;

use openssl::{
    ec::EcKey,
    pkey::{PKey, Private},
};

#[derive(PartialEq, Eq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl FromStr for Environment {
    type Err = ();

    fn from_str(input: &str) -> Result<Environment, Self::Err> {
        match input {
            "staging" => Ok(Environment::Staging),
            "production" => Ok(Environment::Production),
            _ => Ok(Environment::Development),
        }
    }
}

pub fn get_rust_env() -> Environment {
    match std::env::var("RUST_ENV") {
        Ok(env) => Environment::from_str(&env).unwrap(),
        Err(_) => Environment::Development,
    }
}

pub fn get_aws_profile() -> String {
    std::env::var("AWS_PROFILE").unwrap_or_else(|_| "ev-local-customers".to_string())
}


pub fn get_aws_region() -> aws_types::region::Region {
    let region = std::env::var("AWS_REGION")
        .ok()
        .unwrap_or_else(|| "us-east-1".to_string());
    aws_types::region::Region::new(region)
}

#[derive(Clone)]
pub struct EnclaveRunConfig {
    pub num_cpus: String,
    pub ram_size_mib: String,
    pub debug_mode: String,
}

impl EnclaveRunConfig {
    pub fn new(
        num_cpus: String,
        ram_size_mib: String,
        debug_mode: String,
    ) -> EnclaveRunConfig {
        EnclaveRunConfig {
            num_cpus,
            ram_size_mib,
            debug_mode,
        }
    }
}


#[derive(Clone)]
pub struct EnclaveContext {
    pub uuid: String,
    pub version: String,
    pub name: String,
    pub app_uuid: String,
    pub team_uuid: String,
}

impl EnclaveContext {
    pub fn new(
        uuid: String,
        version: String,
        name: String,
        app_uuid: String,
        team_uuid: String,
    ) -> EnclaveContext {
        EnclaveContext {
            uuid,
            version,
            name,
            app_uuid,
            team_uuid,
        }
    }

    pub fn from_env_vars() -> EnclaveContext {
        EnclaveContext {
            uuid: get_enclave_uuid(),
            version: get_enclave_version(),
            name: get_enclave_name(),
            app_uuid: get_app_uuid(),
            team_uuid: get_team_uuid(),
        }
    }

    pub fn hyphenated_app_uuid(&self) -> String {
        self.app_uuid.replace('_', "-")
    }

    pub fn get_namespace_string(&self) -> String {
        format!("{}/{}", self.hyphenated_app_uuid(), self.name)
    }
}

pub fn get_enclave_uuid() -> String {
    std::env::var("CAGE_UUID").expect("CAGE_UUID is not set in env")
}

pub fn get_enclave_version() -> String {
    std::env::var("EV_CAGE_VERSION_ID").expect("EV_CAGE_VERSION_ID is not set in env")
}

pub fn get_enclave_name() -> String {
    std::env::var("EV_CAGE_NAME").expect("EV_CAGE_NAME is not set in env")
}

pub fn get_ec2_instance_id() -> String {
    std::env::var("EC2_INSTANCE_ID").expect("EC2_INSTANCE_ID is not set in env")
}

pub fn get_deregistration_topic_arn() -> String {
    std::env::var("DEREGISTRATION_TOPIC_ARN").expect("DEREGISTRATION_TOPIC_ARN is not set in env")
}

pub fn get_app_uuid() -> String {
    std::env::var("EV_APP_UUID").expect("EV_APP_UUID is not set in env")
}

pub fn get_team_uuid() -> String {
    std::env::var("EV_TEAM_UUID").expect("EV_TEAM_UUID is not set in env")
}

pub fn get_enclave_run_config() -> EnclaveRunConfig {
    let num_cpus = std::env::var("ENCLAVE_NUM_CPUS").unwrap_or_else(|_| "2".to_string());
    let ram_size_mib = std::env::var("ENCLAVE_RAM_SIZE_MIB").unwrap_or_else(|_| "512".to_string());
    let debug_mode = std::env::var("ENCLAVE_DEBUG_MODE").unwrap_or_else(|_| "false".to_string());
    EnclaveRunConfig::new(num_cpus, ram_size_mib, debug_mode)
}

pub fn get_cert_provisoner_host() -> String {
    match get_rust_env() {
        Environment::Staging | Environment::Production => "provisioner.cages.internal".to_string(),
        _ => "localhost".to_string(),
    }
}

pub fn get_acme_hosts() -> Vec<String> {
    vec![
        "acme-v02.api.letsencrypt.org".to_string(),
        "acme.zerossl.com".to_string(),
    ]
}

pub fn get_cert_provisioner_mtls_cert_env() -> Result<String, std::env::VarError> {
    std::env::var("CERT_PROVISIONER_MTLS_CLIENT_CERT")
}

pub fn get_cert_provisioner_mtls_key_env() -> Result<String, std::env::VarError> {
    std::env::var("CERT_PROVISIONER_MTLS_CLIENT_KEY")
}

pub fn get_cert_provisioner_mtls_root_cert_env() -> Result<String, std::env::VarError> {
    std::env::var("CERT_PROVISIONER_MTLS_ROOT_CERT")
}

pub fn get_data_plane_version() -> Result<String, std::env::VarError> {
    std::env::var("DATA_PLANE_VERSION")
}

pub fn get_acme_s3_bucket() -> String {
    std::env::var("ACME_S3_BUCKET").expect("ACME_S3_BUCKET is not set in env")
}

pub fn get_acme_ec_key() -> PKey<Private> {
    let key_string =
        std::env::var("ACME_ACCOUNT_EC_KEY").expect("ACME_ACCOUNT_EC_KEY is not set in env");

    PKey::from_ec_key(
        EcKey::private_key_from_pem(key_string.as_bytes())
            .expect("ACME_ACCOUNT_EC_KEY is not a valid EC key"),
    )
    .expect("ACME_ACCOUNT_EC_KEY is not a valid EC key")
}

pub fn get_acme_hmac_key() -> String {
    std::env::var("ACME_ACCOUNT_HMAC_KEY").expect("ACME_ACCOUNT_HMAC_KEY is not set in env")
}

pub fn get_acme_hmac_key_id() -> String {
    std::env::var("ACME_ACCOUNT_HMAC_KEY_ID").expect("ACME_ACCOUNT_HMAC_KEY_ID is not set in env")
}

pub fn get_trusted_cert_base_domains() -> Vec<String> {
    #[cfg(not(staging))]
    let enclave_base_domains = vec![
        "cage.evervault.com".to_string(),
        "enclave.evervault.com".to_string(),
    ];
    #[cfg(staging)]
    let enclave_base_domains = vec![
        "cage.evervault.dev".to_string(),
        "enclave.evervault.dev".to_string(),
    ];

    enclave_base_domains
}

pub fn get_external_metrics_enabled() -> bool {
    match std::env::var("EXTERNAL_METRICS_ENABLED") {
        Ok(val) => val.to_lowercase() == "true",
        Err(_) => false,
    }
}
