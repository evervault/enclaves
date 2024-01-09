use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Deserializer;
use trust_dns_proto::serialize::binary::BinEncodable;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::Message;
use trust_dns_proto::op::MessageType;
use trust_dns_proto::rr::RData;
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder};
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
    #[error("Protocol not supported, use IPv4 or IPv6")]
    ProtocolNotSupported,
    #[error("Could not obtain lock for IP cache")]
    CouldntObtainLock,
    #[error(transparent)]
    ProtoError(#[from] ProtoError),
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

pub fn check_dns_allowed_for_domain(
    packet: &[u8],
    destinations: EgressDestinations,
) -> Result<(), EgressError> {
    let mut decoder = BinDecoder::new(packet);
    let m = Message::read(&mut decoder)?;
    m.queries()
        .iter()
        .try_for_each(|q| check_domain_allow_list(q.name().to_string(), destinations.clone()))
}

pub fn cache_ip_for_allowlist(packet: &[u8]) -> Result<Vec<u8>, EgressError> {
    let mut decoder = BinDecoder::new(packet);
    let mut m = Message::read(&mut decoder)?;

    let stripped_answers: Vec<Record> = m
        .answers()
        .iter()
        .filter_map(|item| {
            println!("Item {:?}", item);
            match item.data().unwrap() {
                RData::A(ip) => {
                    cache_ip(ip.to_string(), item.clone()).ok();
                    Some(item.clone())
                }
                _ => None,
            }
        })
        .collect();
    println!("The final answer {:?}", stripped_answers);
    let mut result = Message::new();
    let final_result = result
        .set_message_type(MessageType::Response)
        .add_additionals(m.additionals().to_owned())
        .add_answers(stripped_answers)
        .add_queries(m.queries().to_owned());

    final_result.

    println!("NEW MESSAGE {:?}", final_result);
    Ok(final_result.to_bytes().unwrap())
}

fn cache_ip(ip: String, record: Record) -> Result<(), EgressError> {
    let mut cache = match ALLOWED_IPS_FROM_DNS.lock() {
        Ok(cache) => cache,
        Err(_) => return Err(EgressError::CouldntObtainLock),
    };
    cache.insert(
        ip,
        record.name().to_string(),
        Duration::from_secs(record.ttl().into()),
    );
    Ok(())
}

pub fn check_ip_allow_list(
    ip: String,
    allowed_destinations: EgressDestinations,
) -> Result<(), EgressError> {
    if allowed_destinations.allow_all
        || allowed_destinations.ips.contains(&ip)
        || is_valid_ip_from_dns(ip.clone())?
    {
        Ok(())
    } else {
        Err(EgressError::EgressIpNotAllowed(ip))
    }
}

fn is_valid_ip_from_dns(ip: String) -> Result<bool, EgressError> {
    let cache = match ALLOWED_IPS_FROM_DNS.lock() {
        Ok(cache) => cache,
        Err(_) => return Err(EgressError::CouldntObtainLock),
    };
    Ok(cache.get(&ip).is_some())
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
        test_allow_valid_ip_for_all_allowed();
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
            exact: vec![],
            wildcard: vec![],
            allow_all: false,
            ips: vec!["2.2.2.2".to_string()],
        };
        let result = check_ip_allow_list("1.1.1.1".to_string(), destinations);
        assert!(matches!(result, Err(EgressIpNotAllowed(_))));
    }

    fn test_allow_valid_ip() {
        let destinations = EgressDestinations {
            exact: vec![],
            wildcard: vec![],
            allow_all: false,
            ips: vec!["1.1.1.1".to_string()],
        };
        let result = check_ip_allow_list("1.1.1.1".to_string(), destinations);
        assert!(result.is_ok());
    }

    fn test_allow_valid_ip_for_all_allowed() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec![],
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
