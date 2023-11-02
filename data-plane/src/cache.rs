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

#[cfg(feature = "network_egress")]
pub mod dns_cache {
    use cached::ExpiringValueCache;
    use once_cell::sync::Lazy;
    use std::net::Ipv4Addr;
    use tokio::sync::Mutex;

    #[derive(Debug)]
    pub enum DnsCacheError {
        FailedToComputeExpiryTime,
    }

    pub struct DnsCacheEntry((Vec<Ipv4Addr>, std::time::Instant));

    impl DnsCacheEntry {
        pub fn ips(&self) -> &[Ipv4Addr] {
            let (ips, _) = &self.0;
            ips
        }
    }

    impl std::convert::TryFrom<(Vec<Ipv4Addr>, u32)> for DnsCacheEntry {
        type Error = DnsCacheError;

        fn try_from(value: (Vec<Ipv4Addr>, u32)) -> Result<Self, Self::Error> {
            let (records, expiry_seconds) = value;
            let now = std::time::Instant::now();
            let expiry_instant = now
                .checked_add(std::time::Duration::from_secs(expiry_seconds.into()))
                .ok_or(DnsCacheError::FailedToComputeExpiryTime)?;
            Ok(Self((records, expiry_instant)))
        }
    }

    impl cached::CanExpire for DnsCacheEntry {
        fn is_expired(&self) -> bool {
            let now = std::time::Instant::now();
            let (_, expiry_instant) = self.0;
            expiry_instant.cmp(&now) == std::cmp::Ordering::Less
        }
    }

    pub static HOST_TO_IP: Lazy<Mutex<ExpiringValueCache<String, DnsCacheEntry>>> =
        Lazy::new(|| Mutex::new(ExpiringValueCache::with_size(20)));
}

#[cfg(feature = "network_egress")]
pub use dns_cache::*;
