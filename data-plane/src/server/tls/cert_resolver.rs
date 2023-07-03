use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509};

use std::sync::Arc;
use std::sync::RwLock;
#[cfg(not(feature = "enclave"))]
use std::time::Duration;
use std::time::SystemTime;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::sign::{self, CertifiedKey};
use tokio_rustls::rustls::{Certificate, PrivateKey};

use crate::server::error::ServerResult;
use crate::CageContext;

/// Shared struct to implement cert expiry checks and refreshes
struct CertContainer {
    // Need to track both the cert and the expiry time of the AD embedded
    // RwLock needed for interior mutability — we need to swap the cert out from within the resolver when expired
    inner: RwLock<(SystemTime, Arc<CertifiedKey>)>,
}

impl CertContainer {
    fn new(created_at: SystemTime, cert: CertifiedKey) -> Self {
        Self {
            inner: RwLock::new((created_at, Arc::new(cert))),
        }
    }

    fn expiry_time(&self) -> SystemTime {
        self.inner.read().unwrap().0
    }

    fn cert(&self) -> Arc<CertifiedKey> {
        self.inner.read().unwrap().1.clone()
    }

    /// Regenerate the cert with a fresh attestation document.
    /// Takes out an exlusive write lock on the resolver's cert attribute, which is freed before exiting.
    fn rotate_cert<F>(&self, create_new_cert: F) -> ServerResult<Arc<CertifiedKey>>
    where
        F: FnOnce() -> ServerResult<(SystemTime, CertifiedKey)>,
    {
        let mut write_lock = self.inner.write().unwrap();
        let wrapped_cert;
        // sanity check to ensure cert hasn't been refreshed concurrently
        if std::cmp::Ordering::Greater != write_lock.0.cmp(&SystemTime::now()) {
            let (expiry, new_cert) = create_new_cert()?;
            wrapped_cert = Arc::new(new_cert);
            *write_lock = (expiry, wrapped_cert.clone());
        } else {
            // if stored cert is valid, just serve it
            wrapped_cert = write_lock.1.clone();
        }
        drop(write_lock);
        Ok(wrapped_cert)
    }

    fn resolve_cert<F>(&self, create_new_cert: F) -> Option<Arc<CertifiedKey>>
    where
        F: FnOnce() -> ServerResult<(SystemTime, CertifiedKey)>,
    {
        if std::cmp::Ordering::Greater == self.expiry_time().cmp(&SystemTime::now()) {
            // return existing cert
            return Some(self.cert());
        }
        let cert = self
            .rotate_cert(create_new_cert)
            .unwrap_or_else(|_| self.cert());
        Some(cert)
    }
}

/// Implementor of rustls server cert resolver
/// If the request includes a nonce (by hitting <nonce>.attest.<cage_domain>), then this
/// resolver will attempt to serve a fresh, attestable cert with the nonce embedded in the attestation document
/// Standard requests will be served a standard attestable cert as a fallback
pub struct AttestableCertResolver {
    cage_context: CageContext,
    internal_ca: X509,
    internal_pk: PKey<Private>,
    // if we don't receive a nonce, we should return a generic, attestable cert
    base_cert_container: CertContainer,
}

impl AttestableCertResolver {
    pub fn new(internal_ca: X509, internal_pk: PKey<Private>) -> ServerResult<Self> {
        let cage_context = CageContext::get()?;
        let hostname = cage_context.get_cert_name();
        let (created_at, cert_and_key) = Self::generate_self_signed_cert(
            internal_ca.as_ref(),
            internal_pk.as_ref(),
            hostname.as_str(),
            None,
        )?;

        Ok(Self {
            cage_context,
            internal_ca,
            internal_pk,
            base_cert_container: CertContainer::new(created_at, cert_and_key),
        })
    }

    fn extract_nonce_from_servername(received_servername: &str) -> Option<Vec<u8>> {
        let tokens: Vec<&str> = received_servername.split('.').collect();
        if tokens.len() > 2 {
            match (tokens[0], tokens[1]) {
                (nonce, "attest") => base64::decode(nonce).ok(),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Make a X509 request with the given private key
    fn generate_csr(key_pair: &PKey<Private>, hostname: &str) -> Result<X509Req, ErrorStack> {
        let mut req_builder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(key_pair)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "IE")?;
        x509_name.append_entry_by_text("ST", "DUB")?;
        x509_name.append_entry_by_text("O", "Evervault")?;
        // CommonName upper bound is 64 characters
        if hostname.len() < 65 {
            x509_name.append_entry_by_text("CN", hostname)?;
        }

        let x509_name = x509_name.build();
        req_builder.set_subject_name(&x509_name)?;

        req_builder.sign(key_pair, MessageDigest::sha256())?;
        let req = req_builder.build();
        Ok(req)
    }

    #[allow(unused_variables)]
    fn generate_self_signed_cert(
        signing_cert: &X509Ref,
        signing_key: &PKeyRef<Private>,
        hostname: &str,
        nonce: Option<Vec<u8>>,
    ) -> ServerResult<(SystemTime, CertifiedKey)> {
        let ec_group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let ec_key = EcKey::generate(ec_group.as_ref())?;
        let key_pair = PKey::from_ec_key(ec_key)?;

        let req = Self::generate_csr(&key_pair, hostname)?;

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(req.subject_name())?;
        cert_builder.set_issuer_name(signing_cert.subject_name())?;
        cert_builder.set_pubkey(&key_pair)?;
        // 10 second buffer to avoid system times mismatches
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            - 10;
        let not_before = Asn1Time::from_unix(now.try_into()?)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        let mut san_ext = SubjectAlternativeName::new();
        san_ext.dns(hostname);

        #[cfg(feature = "enclave")]
        let expiry_time = Self::append_attestation_info(
            hostname.to_string(),
            Some(key_pair.public_key_to_der()?),
            nonce,
            &mut san_ext,
        )?;
        #[cfg(not(feature = "enclave"))]
        let expiry_time = SystemTime::now() + Duration::from_secs(60 * 60 * 24);

        let ctx = cert_builder.x509v3_context(Some(signing_cert), None);
        let san_ext = san_ext.build(&ctx)?;
        cert_builder.append_extension(san_ext)?;

        let ctx = cert_builder.x509v3_context(Some(signing_cert), None);
        let spki_ext = SubjectKeyIdentifier::new().build(&ctx)?;
        cert_builder.append_extension(spki_ext)?;

        let ctx = cert_builder.x509v3_context(Some(signing_cert), None);
        let auth_key_id_ext = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&ctx)?;
        cert_builder.append_extension(auth_key_id_ext)?;

        cert_builder.sign(signing_key, MessageDigest::sha256())?;

        let generated_cert_and_key = Self::convert_openssl_cert_chain_to_certified_key(
            cert_builder.build(),
            signing_cert.to_owned(),
            key_pair,
        )?;
        Ok((expiry_time, generated_cert_and_key))
    }

    #[cfg(feature = "enclave")]
    fn append_attestation_info(
        hostname: String,
        challenge: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        san_ext: &mut SubjectAlternativeName,
    ) -> ServerResult<SystemTime> {
        use crate::crypto::attest;

        let attestation_doc = attest::get_attestation_doc(challenge, nonce).unwrap();
        let expiry = attest::get_expiry_time(&attestation_doc)?;
        let hex_encoded_ad = shared::utils::HexSlice::from(attestation_doc.as_slice());
        let attestable_san = format!("{hex_encoded_ad:x}.{hostname}");
        san_ext.dns(&attestable_san);
        Ok(expiry)
    }

    fn convert_openssl_cert_chain_to_certified_key(
        leaf_cert: X509,
        intermediate_cert: X509,
        private_key: PKey<Private>,
    ) -> ServerResult<CertifiedKey> {
        let der_encoded_private_key = private_key.private_key_to_der()?;
        let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key))?;
        let pem_encoded_leaf_cert: Vec<u8> = leaf_cert.to_pem()?;
        let pem_encoded_intermediate_cert: Vec<u8> = intermediate_cert.to_pem()?;
        let combined_pem_encoded_certs: Vec<u8> =
            [pem_encoded_leaf_cert, pem_encoded_intermediate_cert].concat();
        let parsed_pems = pem::parse_many(combined_pem_encoded_certs)?;
        let cert_chain: Vec<Certificate> = parsed_pems
            .into_iter()
            .map(|p| Certificate(p.contents))
            .collect();
        let cert_and_key = CertifiedKey::new(cert_chain, ecdsa_private_key);
        Ok(cert_and_key)
    }

    fn resolve_cert_using_sni(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        // sni header should always be some given cages routing approach, fallback to default hostname
        let sni_header = server_name
            .map(String::from)
            .unwrap_or_else(|| self.cage_context.get_cert_name());
        let maybe_decoded_nonce = server_name.and_then(Self::extract_nonce_from_servername);
        // if nonce is set, we need to generate a fresh cert
        if let Some(nonce) = maybe_decoded_nonce {
            let certified_key = Self::generate_self_signed_cert(
                self.internal_ca.as_ref(),
                self.internal_pk.as_ref(),
                sni_header.as_str(),
                Some(nonce),
            )
            .map_err(|err| {
                eprintln!("An error occurred while generating the self signed cert");
                err
            })
            .ok()
            .map(|(_expiry, cert)| Arc::new(cert))?;
            Some(certified_key)
        } else {
            // no nonce given - serve base cert
            self.base_cert_container.resolve_cert(|| {
                let cage_hostname = self.cage_context.get_cert_name();
                Self::generate_self_signed_cert(
                    self.internal_ca.as_ref(),
                    self.internal_pk.as_ref(),
                    cage_hostname.as_str(),
                    None,
                )
            })
        }
    }
}

impl ResolvesServerCert for AttestableCertResolver {
    fn resolve(
        &self,
        client_hello: tokio_rustls::rustls::server::ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        self.resolve_cert_using_sni(client_hello.server_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::AsBytes;
    use openssl::x509::X509;

    fn parse_x509_from_rustls_certified_key(cert: &CertifiedKey) -> X509 {
        let cert_chain = cert.cert.clone();
        let end_node = cert_chain[0].clone();
        X509::from_der(end_node.0.as_bytes()).unwrap()
    }

    macro_rules! get_digest {
        ($cert:expr) => {
            $cert
                .digest(openssl::hash::MessageDigest::sha256())
                .unwrap()
                .as_bytes()
        };
    }

    #[test]
    fn test_base_cert_used_without_nonce() {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_uuid = "cage_123".to_string();
        let cage_name = "my-sick-cage".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_uuid, cage_name);
        let server_name = Some(ctx.get_cert_name());
        CageContext::set(ctx);
        let (cert, key) = generate_ca().unwrap();
        let resolver = AttestableCertResolver::new(cert, key).unwrap();
        let first_cert = resolver
            .resolve_cert_using_sni(server_name.as_deref())
            .unwrap();
        let second_cert = resolver
            .resolve_cert_using_sni(server_name.as_deref())
            .unwrap();

        let first_x509 = parse_x509_from_rustls_certified_key(&first_cert);
        let second_x509 = parse_x509_from_rustls_certified_key(&second_cert);

        assert_eq!(get_digest!(&first_x509), get_digest!(&second_x509));

        // assert that base cert will only be generated for the cage context hostname regardless of sni
        let new_server_name = Some(format!("new-{}", server_name.unwrap()));
        let cert_with_diff_sni = resolver
            .resolve_cert_using_sni(new_server_name.as_deref())
            .unwrap();
        let diff_sni_cert = parse_x509_from_rustls_certified_key(&cert_with_diff_sni);
        assert_eq!(get_digest!(&first_x509), get_digest!(&diff_sni_cert));
    }

    #[test]
    fn test_base_cert_used_with_nonce() {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_uuid = "cage_123".to_string();
        let cage_name = "my-sick-cage".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_uuid, cage_name);
        CageContext::set(ctx.clone());
        let server_name = Some(ctx.get_cert_name());
        let (cert, key) = generate_ca().unwrap();
        let resolver = AttestableCertResolver::new(cert, key).unwrap();
        let first_cert = resolver
            .resolve_cert_using_sni(server_name.as_deref())
            .unwrap();

        let nonce = base64::encode(b"testnonce");
        let server_name_with_nonce =
            server_name.map(|hostname| format!("{nonce}.attest.{hostname}"));
        let cert_with_nonce = resolver
            .resolve_cert_using_sni(server_name_with_nonce.as_deref())
            .unwrap();

        let first_x509 = parse_x509_from_rustls_certified_key(&first_cert);
        let x509_with_nonce = parse_x509_from_rustls_certified_key(&cert_with_nonce);

        // assert that base cert != cert with nonce
        assert_ne!(get_digest!(&first_x509), get_digest!(&x509_with_nonce));

        // assert that certs with nonces are not reused
        let cert_with_same_nonce = resolver
            .resolve_cert_using_sni(server_name_with_nonce.as_deref())
            .unwrap();
        let same_nonce_cert = parse_x509_from_rustls_certified_key(&cert_with_same_nonce);
        assert_ne!(get_digest!(&x509_with_nonce), get_digest!(&same_nonce_cert));
    }

    #[cfg(staging)]
    #[test]
    fn test_tld_is_correct_when_compiler_flag_is_set() {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_uuid = "cage_123".to_string();
        let cage_name = "a-cage".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_uuid, cage_name);
        let hostname = ctx.get_cert_name();
        assert!(hostname.ends_with(".dev"));
    }

    #[test]
    fn test_common_name_not_included_for_long_cage_name() {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_uuid = "cage_123".to_string();
        let cage_name = "a-sick-cage-that-has-a-very-long-name".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_uuid, cage_name);
        let hostname = ctx.get_cert_name();

        if cfg!(staging) {
            assert!(hostname.ends_with(".dev"));
        } else {
            assert!(hostname.ends_with(".com"));
        }

        let server_name = Some(hostname.clone());
        let (cert, key) = generate_ca().unwrap();
        let resolver = AttestableCertResolver::new(cert, key).unwrap();
        let first_cert = resolver
            .resolve_cert_using_sni(server_name.as_deref())
            .unwrap();

        let first_x509 = parse_x509_from_rustls_certified_key(&first_cert);
        // assert that final entry in the subject name is not the hostname
        let x509_subject_name = first_x509.subject_name();
        let final_name_entry = x509_subject_name.entries().find(|entry| {
            let entry_string = entry.data().as_utf8().unwrap();
            entry_string.to_string() == hostname
        });
        assert!(final_name_entry.is_none());
    }

    #[test]
    fn test_common_name_is_included_for_shorter_cage_name() {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_uuid = "cage_123".to_string();
        let cage_name = "my-sick-cage".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_uuid, cage_name);
        let hostname = ctx.get_cert_name();
        if cfg!(staging) {
            assert!(hostname.ends_with(".dev"));
        } else {
            assert!(hostname.ends_with(".com"));
        }

        let server_name = Some(hostname.clone());
        let (cert, key) = generate_ca().unwrap();
        let resolver = AttestableCertResolver::new(cert, key).unwrap();
        let first_cert = resolver
            .resolve_cert_using_sni(server_name.as_deref())
            .unwrap();

        let first_x509 = parse_x509_from_rustls_certified_key(&first_cert);

        // assert that final entry in the subject name is the hostname
        let x509_subject_name = first_x509.subject_name();
        let final_name_entry = x509_subject_name.entries().find(|entry| {
            let entry_string = entry.data().as_utf8().unwrap();
            let given_host = entry_string.to_string();
            given_host == hostname
        });
        assert!(final_name_entry.is_some());
    }

    pub fn generate_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
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
}
