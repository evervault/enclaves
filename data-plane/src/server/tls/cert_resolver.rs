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

use rcgen::Certificate as SelfSignedCertificate;
pub struct SelfSignedCertResolver {
    // Need to track both the cert and the expiry time of the AD embedded
    // RwLock needed for interior mutability — we need to swap the cert out from within the resolver when expired
    cert: RwLock<(SystemTime, Arc<CertifiedKey>)>,
    cage_context: CageContext,
}

impl SelfSignedCertResolver {
    pub fn new(cage_ctx: CageContext) -> ServerResult<Self> {
        let (expiry_time, self_signed_cert) =
            Self::generate_self_signed_cert(cage_ctx.get_cert_name())?;
        Ok(Self {
            cert: RwLock::new((expiry_time, Arc::new(self_signed_cert))),
            cage_context: cage_ctx,
        })
    }

    /// Translate rcgen's `Certificate` type into a rustls compatible `CertifiedKey`
    fn convert_rcgen_cert_to_certified_key(
        cert: SelfSignedCertificate,
    ) -> ServerResult<CertifiedKey> {
        let der_encoded_private_key = cert.serialize_private_key_der();
        let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key))?;
        let pem_encoded_cert = cert.serialize_pem()?;
        let parsed_pems = pem::parse_many(&pem_encoded_cert)?;
        let cert_chain: Vec<Certificate> = parsed_pems
            .into_iter()
            .map(|p| Certificate(p.contents))
            .collect();

        Ok(CertifiedKey::new(cert_chain, ecdsa_private_key))
    }

    /// Use rcgen to generate a self signed cert for the given hostname.
    /// If running with the enclave feature flag, this function will embed the attestation document as an SAN extension.
    fn generate_self_signed_cert(hostname: String) -> ServerResult<(SystemTime, CertifiedKey)> {
        #[cfg(feature = "enclave")]
        let mut cert_alt_names = vec![hostname.clone()];
        #[cfg(not(feature = "enclave"))]
        let cert_alt_names = vec![hostname];

        let expiry_time: SystemTime;
        #[cfg(feature = "enclave")]
        {
            // embded attestation data into the cert, with no support for liveness checks
            use crate::crypto::attest;
            let attestation_doc = attest::get_attestation_doc(None, None)?;
            expiry_time = attest::get_expiry_time(&attestation_doc)?;
            let attestation_hex_slice = shared::utils::HexSlice::from(attestation_doc.as_slice());
            let attestation_san = format!("{attestation_hex_slice:x}.{hostname}");
            cert_alt_names.push(attestation_san);
        }
        #[cfg(not(feature = "enclave"))]
        {
            expiry_time = SystemTime::now() + Duration::from_secs(60 * 60 * 24);
        }

        let self_signed_cert = rcgen::generate_simple_self_signed(cert_alt_names)?;
        // our cert is generated using rcgen, but we're using rustls for tls termination so need to perform a conversion each cert gen
        let compatible_cert = Self::convert_rcgen_cert_to_certified_key(self_signed_cert)?;

        Ok((expiry_time, compatible_cert))
    }

    fn expiry_time(&self) -> SystemTime {
        self.cert.read().unwrap().0
    }

    fn cert(&self) -> Arc<CertifiedKey> {
        self.cert.read().unwrap().1.clone()
    }

    /// Regenerate the cert with a fresh attestation document.
    /// Takes out an exlusive write lock on the resolver's cert attribute, which is freed before exiting.
    fn refresh_cert(&self) -> ServerResult<Arc<CertifiedKey>> {
        let mut write_lock = self.cert.write().unwrap();
        let wrapped_cert;
        // sanity check to ensure cert hasn't been refreshed concurrently
        if std::cmp::Ordering::Greater != write_lock.0.cmp(&SystemTime::now()) {
            let (expiry, new_cert) =
                Self::generate_self_signed_cert(self.cage_context.get_cert_name())?;
            wrapped_cert = Arc::new(new_cert);
            *write_lock = (expiry, wrapped_cert.clone());
        } else {
            // if stored cert is valid, just serve it
            wrapped_cert = write_lock.1.clone();
        }
        drop(write_lock);
        Ok(wrapped_cert)
    }

    /// Implementation of `rustls::server::server_conn::ResolvesServerCert.resolve`
    /// Defined directly on SelfSignedCertResolver to allow for testing as the `ClientHello` type
    /// cannot be constructed outside of `rustls`
    fn resolve_cert(&self) -> Option<Arc<CertifiedKey>> {
        if std::cmp::Ordering::Greater == self.expiry_time().cmp(&SystemTime::now()) {
            // return existing cert
            return Some(self.cert());
        }
        let cert = self.refresh_cert().unwrap_or_else(|_| self.cert());
        Some(cert)
    }
}

impl ResolvesServerCert for SelfSignedCertResolver {
    fn resolve(
        &self,
        _: tokio_rustls::rustls::server::ClientHello,
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.resolve_cert()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::AsBytes;
    use openssl::x509::{X509Ref, X509};

    fn parse_x509_from_rustls_certified_key(cert: &CertifiedKey) -> X509 {
        let mut cert_chain = cert.cert.clone();
        let end_node = cert_chain.pop().unwrap();
        X509::from_der(end_node.0.as_bytes()).unwrap()
    }

    fn create_self_signed_cert_resolver(
        cert_expiry_time: SystemTime,
    ) -> (X509, SelfSignedCertResolver) {
        let app_uuid = "app_123".to_string();
        let team_uuid = "team_456".to_string();
        let cage_name = "my-sick-cage".to_string();
        let ctx = CageContext::new(app_uuid, team_uuid, cage_name);
        let (_, cert) =
            super::SelfSignedCertResolver::generate_self_signed_cert(ctx.get_cert_name()).unwrap();
        let parsed_initial_cert = parse_x509_from_rustls_certified_key(&cert);
        let initial_cert = Arc::new(cert);
        let resolver = SelfSignedCertResolver {
            cert: RwLock::new((cert_expiry_time, initial_cert)),
            cage_context: ctx,
        };
        (parsed_initial_cert, resolver)
    }

    macro_rules! get_digest {
        ($cert:expr) => {
            $cert
                .digest(openssl::hash::MessageDigest::sha256())
                .unwrap()
                .as_bytes()
        };
    }

    fn assert_resolves_same_cert(existing_cert: &X509Ref, resolver: &SelfSignedCertResolver) {
        let maybe_resolved_cert = resolver.resolve_cert();
        assert!(maybe_resolved_cert.is_some());
        let resolved_cert = maybe_resolved_cert.unwrap();
        let resolved_cert = parse_x509_from_rustls_certified_key(resolved_cert.as_ref());
        assert_eq!(get_digest!(&resolved_cert), get_digest!(&existing_cert));
    }

    fn assert_resolves_diff_cert(existing_cert: &X509Ref, resolver: &SelfSignedCertResolver) {
        let maybe_resolved_cert = resolver.resolve_cert();
        assert!(maybe_resolved_cert.is_some());
        let resolved_cert = maybe_resolved_cert.unwrap();
        let resolved_cert = parse_x509_from_rustls_certified_key(resolved_cert.as_ref());
        assert_ne!(get_digest!(&resolved_cert), get_digest!(&existing_cert));
    }

    #[test]
    fn test_self_signed_cert_rotation() {
        // spoof cert expiry to now to guarantee that the cert gets rotated out
        let (initial_cert, cert_resolver) = create_self_signed_cert_resolver(SystemTime::now());
        assert_resolves_diff_cert(initial_cert.as_ref(), &cert_resolver);
    }

    #[test]
    fn test_sequence_of_requests() {
        let delay = Duration::from_secs(2);
        // spoof cert expiry to the near future so we can test a chain of requests
        let ten_seconds_from_now = SystemTime::now() + delay;
        let (parsed_initial_cert, resolver) =
            create_self_signed_cert_resolver(ten_seconds_from_now);
        assert_resolves_same_cert(parsed_initial_cert.as_ref(), &resolver);
        std::thread::sleep(delay);
        assert_resolves_diff_cert(parsed_initial_cert.as_ref(), &resolver);
    }

    use std::sync::Barrier;
    use std::thread::JoinHandle;

    #[test]
    fn test_concurrent_requests() {
        let delay = Duration::from_secs(2);
        // spoof cert expiry to the near future so we can test a chain of requests
        let ten_seconds_from_now = SystemTime::now() + delay;
        let (parsed_initial_cert, resolver) =
            create_self_signed_cert_resolver(ten_seconds_from_now);
        assert_resolves_same_cert(parsed_initial_cert.as_ref(), &resolver);
        std::thread::sleep(delay);

        let thread_count = 5;
        fn create_thread_to_resolve_cert(
            resolver: Arc<SelfSignedCertResolver>,
            barrier: Arc<Barrier>,
        ) -> JoinHandle<X509> {
            std::thread::spawn(move || {
                // each thread will block until they've all reached this point
                barrier.wait();
                let maybe_resolved_cert = resolver.resolve_cert();
                assert!(maybe_resolved_cert.is_some());
                let certified_key = maybe_resolved_cert.unwrap();
                parse_x509_from_rustls_certified_key(certified_key.as_ref())
            })
        }

        let wrapped_resolver = Arc::new(resolver);
        let mut threads = Vec::with_capacity(thread_count);
        let barrier = Arc::new(Barrier::new(thread_count));
        for _ in 0..thread_count {
            let thread_handle =
                create_thread_to_resolve_cert(wrapped_resolver.clone(), barrier.clone());
            threads.push(thread_handle);
        }

        let cert_from_removed_thread = threads.pop().unwrap().join().unwrap();
        threads.into_iter().for_each(|thread_handle| {
            let resolved_cert = thread_handle.join().unwrap();
            assert_eq!(
                get_digest!(&cert_from_removed_thread),
                get_digest!(&resolved_cert)
            );
        });
    }
}
