use cached::TimedSizedCache;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::crypto::token::AttestationAuth;

const E3_TOKEN_LIFETIME: u64 = 280;

pub static E3_TOKEN: Lazy<Mutex<TimedSizedCache<String, AttestationAuth>>> = Lazy::new(|| {
    Mutex::new(TimedSizedCache::with_size_and_lifespan(
        1,
        E3_TOKEN_LIFETIME,
    ))
});
