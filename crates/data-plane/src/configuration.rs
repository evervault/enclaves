#[cfg(feature = "enclave")]
pub fn get_cert_provisioner_host() -> String {
    "provisioner.cages.internal".to_string()
}

#[cfg(not(feature = "enclave"))]
pub fn get_cert_provisioner_host() -> String {
    "localhost".to_string()
}

pub fn get_acme_host() -> String {
    "acme-v02.api.letsencrypt.org".to_string()
}

pub fn get_acme_base_path() -> String {
    "/directory".to_string()
}

#[cfg(feature = "enclave")]
pub fn get_e3_host() -> String {
    "e3.cages-e3.internal".to_string()
}

#[cfg(not(feature = "enclave"))]
pub fn get_e3_host() -> String {
    "localhost".to_string()
}

pub fn should_forward_proxy_protocol() -> bool {
    std::env::var("FORWARD_PROXY_PROTOCOL").is_ok()
}

pub const DEFAULT_TARGET_PORT: u16 = 8008;

/// The data plane is invoked with the port that it needs to forward traffic to as the 
/// only positional argument.
/// 
/// This function attempts to parse out a u16 value from the index 1 in the process args,
/// returning None if parsing fails.
pub fn parse_target_port_from_args() -> Option<u16> {
    let mut args = std::env::args();
    let _ = args.next(); // ignore path to executable
    args
      .next()
      .and_then(|port_str| port_str.as_str().parse::<u16>().ok())
}
