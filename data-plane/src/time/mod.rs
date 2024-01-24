use libc::{clock_settime, timespec, CLOCK_REALTIME};
use std::io::Error;
use std::time::SystemTimeError;
use thiserror::Error;
use tokio::time;
use tokio::time::Duration;

use crate::config_client::ConfigClient;
use crate::config_client::StorageConfigClientInterface;
use crate::error::Error as DataPlaneError;

#[derive(Error, Debug)]
pub enum ClockSyncError {
    #[error(transparent)]
    Error(#[from] DataPlaneError),
    #[error("Clock sync error: {0}")]
    SyncError(String),
    #[error("Clock sync error: {0}")]
    SystemTimeError(#[from] SystemTimeError),
}
pub struct ClockSync;

impl ClockSync {
    pub async fn run(interval_duration: Duration) {
        let mut interval = time::interval(interval_duration);
        let config_client = ConfigClient::new();
        loop {
            interval.tick().await;
            if let Err(e) = Self::sync_time_from_host(&config_client).await {
                log::error!("{e:?}")
            }
        }
    }

    async fn sync_time_from_host(config_client: &ConfigClient) -> Result<(), ClockSyncError> {
        let request_timer = std::time::SystemTime::now();
        let time = config_client.get_time_from_host().await?;
        let elapsed = request_timer.elapsed()?;

        // On startup the request can take a while so skip the sync till the proxies have stabilized
        if elapsed.as_millis() > 500 {
            log::info!(
                "Skipping clock sync because request took {}ms",
                elapsed.as_millis()
            );
            return Ok(());
        }
        let ts = timespec {
            tv_sec: time.seconds,
            tv_nsec: time.milliseconds,
        };

        let result = unsafe { clock_settime(CLOCK_REALTIME, &ts as *const timespec) };
        if result == 0 {
            log::info!(
                "Enclave time synced with host succesfully - {}.{}s. Request round trip took {}ns",
                time.seconds,
                time.milliseconds,
                elapsed.as_nanos()
            );
            Ok(())
        } else {
            Err(ClockSyncError::SyncError(format!(
                "Could not sync enclave time with host {:?}",
                Error::last_os_error()
            )))
        }
    }
}
