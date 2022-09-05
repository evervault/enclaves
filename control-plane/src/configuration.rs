use std::str::FromStr;

use rusoto_core::Region;

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

pub fn get_aws_region() -> Region {
    std::env::var("AWS_REGION")
        .map(|region| Region::from_str(&region))
        .unwrap_or(Ok(Region::UsEast1))
        .expect("Expected AWS Region to be set under AWS_PROFILE")
}

pub fn get_cage_uuid() -> String {
    std::env::var("CAGE_UUID").expect("CAGE_UUID is not set in env")
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
