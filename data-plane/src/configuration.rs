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

pub fn get_egress_ports() -> Vec<u16> {
    let port_str = std::env::var("EGRESS_PORTS").unwrap_or("443".to_string());
    port_str
        .split(',')
        .map(|port| {
            port.parse::<u16>()
                .unwrap_or_else(|_| panic!("Could not parse egress port as u16: {port}"))
        })
        .collect()
}

pub fn get_egress_allow_list() -> EgressDomains {
    let domain_str = std::env::var("EGRESS_ALLOW_LIST").unwrap_or("".to_string());
    let domains: Vec<String> = domain_str
        .split(',')
        .map(|domain| domain.to_string())
        .collect();
    let (wildcard, exact): (Vec<String>, Vec<String>) = domains
        .clone()
        .into_iter()
        .partition(|domain| domain.starts_with("*."));
    let wildcard_stripped = wildcard
        .iter()
        .filter_map(|w| w.strip_prefix("*.").map(|domain| domain.to_string()))
        .collect();
    EgressDomains {
        wildcard: wildcard_stripped,
        exact,
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct EgressDomains {
    pub wildcard: Vec<String>,
    pub exact: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::{configuration::{get_egress_allow_list, EgressDomains}};

    #[test]
    fn test_valid_all_domains() {
        std::env::set_var("EGRESS_ALLOW_LIST", "*");
        let egress = get_egress_allow_list();
        assert_eq!(egress, EgressDomains { exact: vec!["*".to_string()], wildcard: vec![]})
    }

    #[test]
    fn test_wildcard_and_exact() {
        std::env::set_var("EGRESS_ALLOW_LIST", "*.evervault.com,google.com");
        let egress = get_egress_allow_list();
        assert_eq!(egress, EgressDomains { exact: vec!["google.com".to_string()], wildcard: vec!["evervault.com".to_string()]})
    }
}