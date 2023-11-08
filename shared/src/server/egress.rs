use serde::Deserialize;
use serde::Deserializer;
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

pub fn get_egress_allow_list_from_env() -> EgressDomains {
    let domain_str = std::env::var("EV_EGRESS_ALLOW_LIST").unwrap_or("".to_string());
    get_egress_allow_list(domain_str)
}

pub fn get_egress_allow_list(domain_str: String) -> EgressDomains {
    let (wildcard, exact): (Vec<String>, Vec<String>) = domain_str
        .split(',')
        .map(|domain| domain.to_string())
        .partition(|domain| domain.starts_with("*."));
    let wildcard_stripped = wildcard
        .iter()
        .filter_map(|wc| wc.strip_prefix('*').map(|domain| domain.to_string()))
        .collect();
    EgressDomains {
        wildcard: wildcard_stripped,
        exact: exact.clone(),
        allow_all: exact == vec![""] || exact.contains(&"*".to_string()),
    }
}

pub fn check_allow_list(
    hostname: String,
    allowed_domains: EgressDomains,
) -> Result<(), EgressError> {
    let valid_wildcard = allowed_domains
        .wildcard
        .iter()
        .any(|wildcard| hostname.ends_with(wildcard));

    if allowed_domains.exact.contains(&hostname) || allowed_domains.allow_all || valid_wildcard {
        Ok(())
    } else {
        Err(EgressError::EgressDomainNotAllowed(hostname))
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct EgressDomains {
    pub wildcard: Vec<String>,
    pub exact: Vec<String>,
    pub allow_all: bool,
}

fn deserialize_allowlist<'de, D>(deserializer: D) -> Result<EgressDomains, D::Error>
where
    D: Deserializer<'de>,
{
    let allow_list: String = Deserialize::deserialize(deserializer)?;
    Ok(get_egress_allow_list(allow_list))
}

fn deserialize_ports<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let ports: String = Deserialize::deserialize(deserializer)?;
    Ok(get_egress_ports(ports))
}

#[derive(Clone, Deserialize)]
pub struct EgressConfig {
    #[serde(deserialize_with = "deserialize_ports")]
    pub ports: Vec<u16>,
    #[serde(deserialize_with = "deserialize_allowlist")]
    pub allow_list: EgressDomains,
}

pub fn get_egress_ports(port_str: String) -> Vec<u16> {
    port_str
        .split(',')
        .map(|port| {
            port.parse::<u16>()
                .unwrap_or_else(|_| panic!("Could not parse egress port as u16: {port}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::server::egress::get_egress_allow_list_from_env;
    use crate::server::egress::EgressDomains;

    #[test]
    fn test_sequentially() {
        test_valid_all_domains();
        test_wildcard_and_exact();
        test_backwards_compat();
    }

    fn test_valid_all_domains() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "*");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDomains {
                exact: vec!["*".to_string()],
                wildcard: vec![],
                allow_all: true
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST");
    }

    fn test_wildcard_and_exact() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "*.evervault.com,google.com");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDomains {
                exact: vec!["google.com".to_string()],
                wildcard: vec![".evervault.com".to_string()],
                allow_all: false
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST");
    }

    fn test_backwards_compat() {
        std::env::set_var("EV_EGRESS_ALLOW_LIST", "");
        let egress = get_egress_allow_list_from_env();
        assert_eq!(
            egress,
            EgressDomains {
                exact: vec!["".to_string()],
                wildcard: vec![],
                allow_all: true
            }
        );
        std::env::remove_var("EV_EGRESS_ALLOW_LIST")
    }
}
