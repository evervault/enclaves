use thiserror::Error;
use tls_parser::{
    nom::Finish, parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};

#[derive(Debug, Error)]

pub enum SNIError {
    #[error("Couldn't parse hostname from request {0}")]
    HostnameError(String),
    #[error("Attempted request to banned domain {0}")]
    EgressDomainNotAllowed(String),
    #[error("Client Hello not found")]
    ClientHelloMissing,
    #[error("TLS extension missing")]
    ExtensionMissing,
}

pub fn get_hostname(data: Vec<u8>) -> Result<String, SNIError> {
    let (_, parsed_request) = parse_tls_plaintext(&data)
        .finish()
        .map_err(|tls_parse_err| SNIError::HostnameError(format!("{tls_parse_err:?}")))?;

    let client_hello = match &parsed_request.msg[0] {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => client_hello,
        _ => return Err(SNIError::ClientHelloMissing),
    };

    let raw_extensions = match client_hello.ext {
        Some(raw_extensions) => raw_extensions,
        _ => return Err(SNIError::ExtensionMissing),
    };
    let mut destination = "".to_string();
    let (_, extensions) = parse_tls_extensions(raw_extensions)
        .finish()
        .map_err(|tls_parse_err| SNIError::HostnameError(format!("{tls_parse_err:?}")))?;

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

