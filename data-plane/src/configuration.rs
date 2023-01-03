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
