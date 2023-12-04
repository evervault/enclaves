use serde::Deserialize;
use serde::Deserializer;
use std::net::Ipv4Addr;
use thiserror::Error;
use tls_parser::{
    nom::Finish, parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};

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
}

pub fn get_hostname(data: Vec<u8>) -> Result<String, EgressError> {
    let (_, parsed_request) = parse_tls_plaintext(&data)
        .finish()
        .map_err(|tls_parse_err| EgressError::HostnameError(format!("{tls_parse_err:?}")))?;

    let client_hello = match &parsed_request.msg[0] {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => client_hello,
        _ => return Err(EgressError::ClientHelloMissing),
    };

    let raw_extensions = match client_hello.ext {
        Some(raw_extensions) => raw_extensions,
        _ => return Err(EgressError::ExtensionMissing),
    };
    let mut destination = "".to_string();
    let (_, extensions) = parse_tls_extensions(raw_extensions)
        .finish()
        .map_err(|tls_parse_err| EgressError::HostnameError(format!("{tls_parse_err:?}")))?;

    for extension in extensions {
        if let TlsExtension::SNI(sni_vec) = extension {
            for (_, item) in sni_vec {
                if let Ok(hostname) = std::str::from_utf8(item) {
                    destination = hostname.to_string();
                }
            }
        }
    }
    Ok(destination)
}

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

pub fn check_allow_list(
    hostname: Option<String>,
    ip: String,
    allowed_destinations: EgressDestinations,
) -> Result<(), EgressError> {
    match hostname {
        Some(domain) => {
            let valid_wildcard = allowed_destinations
                .wildcard
                .iter()
                .any(|wildcard| domain.ends_with(wildcard));
            if allowed_destinations.exact.contains(&domain)
                || allowed_destinations.allow_all
                || valid_wildcard
                || allowed_destinations.ips.contains(&ip)
            {
                Ok(())
            } else {
                Err(EgressError::EgressDomainNotAllowed(domain))
            }
        }
        None if allowed_destinations.ips.contains(&ip) => Ok(()),
        None => Err(EgressError::EgressIpNotAllowed(ip)),
    }
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
    use crate::server::egress::check_allow_list;
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
        let result = check_allow_list(
            Some("invalid.domain.com".to_string()),
            "1.1.1.1".to_string(),
            destinations,
        );
        assert!(matches!(result, Err(EgressDomainNotAllowed(_))));
    }

    fn test_block_invalid_ip() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["2.2.2.2".to_string()],
        };
        let result = check_allow_list(None, "1.1.1.1".to_string(), destinations);
        assert!(matches!(result, Err(EgressIpNotAllowed(_))));
    }

    fn test_allow_valid_ip() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["1.1.1.1".to_string()],
        };
        let result = check_allow_list(None, "1.1.1.1".to_string(), destinations);
        assert!(result.is_ok());
    }

    fn test_allow_valid_domain() {
        let destinations = EgressDestinations {
            exact: vec!["*".to_string()],
            wildcard: vec![],
            allow_all: true,
            ips: vec!["1.1.1.1".to_string()],
        };
        let result = check_allow_list(None, "1.1.1.1".to_string(), destinations);
        assert!(result.is_ok());
    }
}
