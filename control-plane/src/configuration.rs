use std::str::FromStr;

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
pub struct CageContext {
    pub cage_uuid: String,
    pub cage_version: String,
    pub cage_name: String,
    pub app_uuid: String,
    pub team_uuid: String,
}

impl CageContext {
    pub fn new(
        cage_uuid: String,
        cage_version: String,
        cage_name: String,
        app_uuid: String,
        team_uuid: String,
    ) -> CageContext {
        CageContext {
            cage_uuid,
            cage_version,
            cage_name,
            app_uuid,
            team_uuid,
        }
    }

    pub fn from_env_vars() -> CageContext {
        CageContext {
            cage_uuid: get_cage_uuid(),
            cage_version: get_cage_version(),
            cage_name: get_cage_name(),
            app_uuid: get_app_uuid(),
            team_uuid: get_team_uuid(),
        }
    }
}

pub fn get_cage_uuid() -> String {
    std::env::var("CAGE_UUID").expect("CAGE_UUID is not set in env")
}

pub fn get_cage_version() -> String {
    std::env::var("EV_CAGE_VERSION_ID").expect("EV_CAGE_VERSION_ID is not set in env")
}

pub fn get_cage_name() -> String {
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

pub fn get_cert_provisoner_host() -> String {
    match get_rust_env() {
        Environment::Staging | Environment::Production => "provisioner.cages.internal".to_string(),
        _ => "localhost".to_string(),
    }
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

pub fn get_acme_s3_bucket() -> Result<String, std::env::VarError> {
    std::env::var("ACME_S3_BUCKET")
}
