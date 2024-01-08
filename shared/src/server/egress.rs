use dns_parser::RData;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Deserializer;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use ttl_cache::TtlCache;

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("Couldn't parse hostname from request {0}")]
    HostnameError(String),
    #[error("Attempted request to banned domain {0}")]
    EgressDomainNotAllowed(String),
    #[error("Attempted request to banned ip. hostname: {0}")]
    EgressIpNotAllowed(String),
    #[error("Client Hello not found")]
    ClientHelloMissing,
    #[error("TLS extension missing")]
    ExtensionMissing,
    #[error(transparent)]
    DNSParseError(#[from] dns_parser::Error),
    #[error("Protocol not support, only IPv4 is supported")]
    ProtocolNotSupported,
    #[error("Could not obtain lock for IP cache")]
    CouldntObtainLock,
}

pub static ALLOWED_IPS_FROM_DNS: Lazy<Mutex<TtlCache<String, String>>> =
    Lazy::new(|| Mutex::new(TtlCache::new(1000)));

pub fn get_egress_allow_list_from_env() -> EgressDestinations {
    let domain_str = std::env::var("EV_EGRESS_ALLOW_LIST").unwrap_or("".to_string());
    get_egress_allow_list(domain_str)
}

pub fn get_egress_allow_list(domain_str: String) -> EgressDestinations {
    let (ips, domains): (Vec<String>, Vec<String>) = domain_str
        .split(',')
        .map(|destination| destination.to_string())
        .partition(|destination| destination.parse::<Ipv4Addr>().is_ok());
    let (wildcard, exact): (Vec<String>, Vec<String>) = domains
        .iter()
        .map(|domain| domain.to_string())
        .partition(|domain| domain.starts_with("*."));
    let wildcard_stripped = wildcard
        .iter()
        .filter_map(|wc| wc.strip_prefix('*').map(|domain| domain.to_string()))
        .collect();
    EgressDestinations {
        wildcard: wildcard_stripped,
        exact: exact.clone(),
        allow_all: exact == vec![""] || exact.contains(&"*".to_string()),
        ips,
    }
}

pub fn check_domain_allow_list(
    domain: String,
    allowed_destinations: EgressDestinations,
) -> Result<(), EgressError> {
    let valid_wildcard = allowed_destinations
        .wildcard
        .iter()
        .any(|wildcard| domain.ends_with(wildcard));
    if allowed_destinations.exact.contains(&domain)
        || allowed_destinations.allow_all
        || valid_wildcard
    {
        Ok(())
    } else {
        Err(EgressError::EgressDomainNotAllowed(domain))
    }
}

pub fn check_dns_packet(
    packet: &[u8],
    destinations: EgressDestinations,
) -> Result<(), EgressError> {
    let packet = dns_parser::Packet::parse(packet)?;
    packet
        .questions
        .iter()
        .try_for_each(|q| check_domain_allow_list(q.qname.to_string(), destinations.clone()))
}

pub fn cache_dns_packet(packet: &[u8]) -> Result<(), EgressError> {
    let packet = dns_parser::Packet::parse(packet)?;
    let answers: &dns_parser::ResourceRecord<'_> = packet.answers.first().unwrap();
    let ip = get_ip(&answers.data)?;
    let _ = cache_ip(ip.to_string(), answers.name.to_string());
    Ok(())
}

fn cache_ip(ip: String, domain: String) -> Result<(), EgressError> {
    let mut cache = ALLOWED_IPS_FROM_DNS.lock().unwrap(); // TODO: handle error properly
    cache.insert(ip, domain, Duration::from_secs(300));
    Ok(())
}

fn get_ip(data: &RData<'_>) -> Result<Ipv4Addr, EgressError> {
    match data {
        RData::A(ip) => Ok(ip.0),
        _ => Err(EgressError::ProtocolNotSupported),
    }
}

pub fn check_ip_allow_list(
    ip: String,
    allowed_destinations: EgressDestinations,
) -> Result<(), EgressError> {
    if allowed_destinations.ips.contains(&ip) || check_dns_ip(ip.clone()) {
        Ok(())
    } else {
        Err(EgressError::EgressIpNotAllowed(ip))
    }
}

fn check_dns_ip(ip: String) -> bool {
    let binding = ALLOWED_IPS_FROM_DNS.lock().unwrap();
    binding.get(&ip).is_some()
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct EgressDestinations {
    pub wildcard: Vec<String>,
    pub exact: Vec<String>,
    pub allow_all: bool,
    pub ips: Vec<String>,
}

fn deserialize_allowlist<'de, D>(deserializer: D) -> Result<EgressDestinations, D::Error>
where
    D: Deserializer<'de>,
{
    let allow_list: String = Deserialize::deserialize(deserializer)?;
    Ok(get_egress_allow_list(allow_list))
}

#[derive(Clone, Deserialize, Debug)]
pub struct EgressConfig {
    #[serde(deserialize_with = "deserialize_allowlist")]
    pub allow_list: EgressDestinations,
}

#[cfg(test)]
mod tests {
    use crate::server::egress::check_domain_allow_list;
    use crate::server::egress::check_ip_allow_list;
    use crate::server::egress::get_egress_allow_list_from_env;
    use crate::server::egress::EgressDestinations;
    use crate::server::egress::EgressError::{EgressDomainNotAllowed, EgressIpNotAllowed};

    #[test]
    fn test_sequentially() {
        test_valid_all_domains();
        test_wildcard_exact_and_ip();
        test_backwards_compat();
        test_block_invalid_domain();
        test_block_invalid_ip();
        test_allow_valid_ip();
        test_allow_valid_domain();
    }

    fn test_valid_all_domains() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "*");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDestinations {
                exact: vec!["*".to_string()],
                wildcard: vec![],
                allow_all: true,
                ips: vec![]
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST");
    }

    fn test_wildcard_exact_and_ip() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "*.evervault.com,google.com,1.1.1.1");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDestinations {
                exact: vec!["google.com".to_string()],
                wildcard: vec![".evervault.com".to_string()],
                allow_all: false,
                ips: vec!["1.1.1.1".to_string()]
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST");
    }

    fn test_backwards_compat() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDestinations {
                exact: vec!["".to_string()],
                wildcard: vec![],
                allow_all: true,
                ips: vec![]
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST")
    }

    fn test_block_invalid_domain() {
        let destinations = EgressDestinations {
            exact: vec!["my.api.com".to_string()],
            wildcard: vec![],
            allow_all: false,
            ips: vec![],
        };
        let result = check_domain_allow_list("invalid.domain.com".to_string(), destinations);
        assert!(matches!(result, Err(EgressDomainNotAllowed(_))));
    }

    fn test_block_invalid_ip() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["2.2.2.2".to_string()],
        };
        let result = check_ip_allow_list("1.1.1.1".to_string(), destinations);
        assert!(matches!(result, Err(EgressIpNotAllowed(_))));
    }

    fn test_allow_valid_ip() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["1.1.1.1".to_string()],
        };
        let result = check_ip_allow_list("1.1.1.1".to_string(), destinations);
        assert!(result.is_ok());
    }

    fn test_allow_valid_domain() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["1.1.1.1".to_string()],
        };
        let result = check_domain_allow_list("a.domain.com".to_string(), destinations);
        assert!(result.is_ok());
    }
}
