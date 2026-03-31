use cached::TimedSizedCache;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::crypto::token::AttestationAuth;

const E3_TOKEN_LIFETIME: u64 = 280;
const ATTESTATION_DOC_LIFETIME: u64 = 300; // 5 minutes

pub static E3_TOKEN: Lazy<Mutex<TimedSizedCache<String, AttestationAuth>>> = Lazy::new(|| {
    Mutex::new(TimedSizedCache::with_size_and_lifespan(
        1,
        E3_TOKEN_LIFETIME,
    ))
});

pub static ATTESTATION_DOC: Lazy<Mutex<TimedSizedCache<String, String>>> = Lazy::new(|| {
    Mutex::new(TimedSizedCache::with_size_and_lifespan(
        1,
        ATTESTATION_DOC_LIFETIME,
    ))
});
