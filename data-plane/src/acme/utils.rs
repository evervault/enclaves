use std::time::{Duration, SystemTime};

use openssl::asn1::Asn1Time;
use openssl::asn1::Asn1TimeRef;
use rand::Rng;

use super::error::AcmeError;

pub const CERTIFICATE_LOCK_NAME: &str = "certificate-v1";
pub const CERTIFICATE_OBJECT_KEY: &str = "certificate-v1.pem";
pub const ONE_DAY_IN_SECONDS: u64 = 86400;
pub const THIRTY_DAYS_IN_SECONDS: u64 = ONE_DAY_IN_SECONDS * 30;
pub const SIXTY_DAYS_IN_SECONDS: u64 = ONE_DAY_IN_SECONDS * 60;

pub(crate) fn asn1_time_to_system_time(time: &Asn1TimeRef) -> Result<SystemTime, AcmeError> {
    let unix_time = Asn1Time::from_unix(0)?.diff(time)?;
    Ok(SystemTime::UNIX_EPOCH
        + Duration::from_secs(unix_time.days as u64 * 86400 + unix_time.secs as u64))
}

pub(crate) fn get_jittered_time(base_time: SystemTime) -> SystemTime {
    let mut rng = rand::thread_rng();
    let jitter_duration = Duration::from_secs(rng.gen_range(1..86400));
    base_time + jitter_duration
}

pub(crate) fn seconds_with_jitter_to_time(seconds: u64) -> Result<Duration, AcmeError> {
    let time = SystemTime::now() + Duration::from_secs(seconds);
    let jittered_time = get_jittered_time(time);
    jittered_time
        .duration_since(SystemTime::now())
        .map_err(AcmeError::SystemTimeError)
}
