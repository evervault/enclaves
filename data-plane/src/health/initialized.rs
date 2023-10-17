pub trait InitializedHealthcheck {
    type Error: std::error::Error;
    fn is_initialized(&self) -> Result<bool, Self::Error>;
}

pub struct EnclaveEnvInitialized;

impl InitializedHealthcheck for EnclaveEnvInitialized {
    type Error = std::io::Error;

    fn is_initialized(&self) -> Result<bool, Self::Error> {
        let contents = std::fs::read_to_string("/etc/customer-env")?;
        Ok(contents.contains("EV_CAGE_INITIALIZED"))
    }
}
