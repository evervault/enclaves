use thiserror::Error;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};

#[derive(Debug, Error)]

pub enum SNIError {
    #[error("Failed to parse hostname from packet")]
    HostnameError,
    #[error("Attempted request to banned domain {0}")]
    EgressDomainNotAllowed(String),
    #[error("Client Hello not found")]
    ClientHelloMissing,
    #[error("TLS extension missing")]
    ExtensionMissing,
    #[error("Insufficient data received to parse client hello")]
    IncompleteHelloReceived,
}

impl<T> std::convert::From<tls_parser::nom::Err<T>> for SNIError {
    fn from(value: tls_parser::nom::Err<T>) -> Self {
        match value {
            tls_parser::Err::Incomplete(_) => SNIError::IncompleteHelloReceived,
            tls_parser::Err::Error(_) | tls_parser::Err::Failure(_) => SNIError::HostnameError,
        }
    }
}

pub fn get_hostname(data: &[u8]) -> Result<String, SNIError> {
    let (_, parsed_request) = parse_tls_plaintext(data).map_err(SNIError::from)?;

    let client_hello = match &parsed_request.msg[0] {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => client_hello,
        _ => return Err(SNIError::ClientHelloMissing),
    };

    let raw_extensions = match client_hello.ext {
        Some(raw_extensions) => raw_extensions,
        _ => return Err(SNIError::ExtensionMissing),
    };

    let mut destination = "".to_string();
    let (_, extensions) = parse_tls_extensions(raw_extensions).map_err(SNIError::from)?;

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
