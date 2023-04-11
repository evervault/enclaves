use aws_nitro_enclaves_nsm_api as nitro;
use thiserror::Error;

/// Thin wrapper on the NSM API which handles initialization and cleanup.
pub struct NsmConnection(i32);

#[derive(Debug, Error)]
pub enum NsmConnectionError {
    #[error("Failed to initialize NSM connection")]
    InitFailed,
}

impl NsmConnection {
    pub fn try_new() -> Result<Self, NsmConnectionError> {
        let nsm_fd = nitro::driver::nsm_init()();
        if nsm_fd < 0 {
            return Err(NsmConnectionError::InitFailed);
        }
        Ok(Self(nsm_fd))
    }

    pub fn fd(&self) -> i32 {
        self.0
    }
}

impl std::ops::Drop for NsmConnection {
    fn drop(&mut self) {
        nitro::driver::nsm_exit(self.fd());
    }
}
