#[cfg(feature = "enclave")]
pub fn get_cert_provisioner_host() -> String {
    "provisioner.cages.internal".to_string()
}

#[cfg(not(feature = "enclave"))]
pub fn get_cert_provisioner_host() -> String {
    "localhost".to_string()
}

#[cfg(feature = "enclave")]
pub fn get_e3_host() -> String {
    "e3.cages-e3.internal".to_string()
}

#[cfg(not(feature = "enclave"))]
pub fn get_e3_host() -> String {
    "localhost".to_string()
}

pub fn trx_logging_enabled() -> bool {
    //Check if logging enabled - default to true
    match std::env::var("EV_TRX_LOGGING_ENABLED") {
        Ok(var_value) => var_value.parse().unwrap_or(true),
        Err(_) => true,
    }
}

pub fn api_key_auth_enabled() -> bool {
    //Check if api key auth is enabled - default to true
    match std::env::var("EV_API_KEY_AUTH") {
        Ok(auth_enabled) => auth_enabled.parse().unwrap_or(true),
        Err(_) => true,
    }
}
