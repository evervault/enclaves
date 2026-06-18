use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509};
use tokio_rustls::rustls::sign::{self, CertifiedKey};
use tokio_rustls::rustls::{Certificate, PrivateKey};

/// Self-signed CA cert + key (used to stand in for the intermediate CA the
/// provisioner would hand the data plane).
pub(crate) fn generate_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec_key = EcKey::generate(ec_group.as_ref())?;
    let key_pair = PKey::from_ec_key(ec_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "IE")?;
    x509_name.append_entry_by_text("ST", "DUB")?;
    x509_name.append_entry_by_text("O", "Evervault")?;
    x509_name.append_entry_by_text("CN", "Data Plane Self Signed Cert")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok((cert, key_pair))
}

/// A standalone self-signed leaf cert + key.
pub(crate) fn generate_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec_key = EcKey::generate(ec_group.as_ref())?;
    let key_pair = PKey::from_ec_key(ec_key)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "IE")?;
    x509_name.append_entry_by_text("ST", "DUB")?;
    x509_name.append_entry_by_text("O", "Evervault")?;
    x509_name.append_entry_by_text("CN", "test_enclave.app123654.enclave.evervault.dev")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

/// A rustls [`CertifiedKey`] for a standalone leaf cert (used to seed the
/// trusted cert store in tests).
pub(crate) fn generate_end_cert() -> CertifiedKey {
    let (cert, key) = generate_cert().unwrap();
    let der_encoded_private_key = key.private_key_to_der().unwrap();
    let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key)).unwrap();
    let pem_encoded_cert: Vec<u8> = cert.to_pem().unwrap();
    let parsed_pem = pem::parse(&pem_encoded_cert).unwrap();
    let cert_chain: Vec<Certificate> = vec![Certificate(parsed_pem.contents)];
    CertifiedKey::new(cert_chain, ecdsa_private_key)
}

/// Build a real `TlsAcceptor` backed by the attestable cert resolver and a
/// freshly-generated CA, for the end-to-end harness. Requires the global
/// `EnclaveContext` to be seeded (the resolver reads it).
pub(crate) fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use crate::server::tls::cert_resolver::AttestableCertResolver;
    use std::sync::Arc;
    use tokio_rustls::rustls::ServerConfig;

    let (ca_cert, ca_key) = generate_ca().expect("generate CA");
    let resolver =
        AttestableCertResolver::new(ca_cert, ca_key).expect("EnclaveContext must be seeded");
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols.push(b"http/1.1".to_vec());
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
