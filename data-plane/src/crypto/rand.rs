use crate::error::{Error, Result};

#[cfg(enclave)]
pub fn rand_bytes(buffer: &mut [u8]) -> Result<()> {
    use aws_nitro_enclaves_nsm_api as nitro;
    match nitro::driver::nsm_process_request(
        nitro::driver::nsm_init(),
        nitro::api::Request::GetRandom,
    ) {
        nitro::api::Response::GetRandom { random } => Ok(buffer.copy_from_slice(&random)),
        nitro::api::Response::Error(e) => Err(Error::Crypto(format!(
            "Could not get entropy from the Nitro Secure Module! {:?}",
            e
        ))),
        _ => Err(Error::Crypto(
            "Received unknown response from Nitro Secure Module".to_string(),
        )),
    }
}

#[cfg(not(enclave))]
pub fn rand_bytes(buffer: &mut [u8]) -> Result<()> {
    openssl::rand::rand_bytes(buffer).map_err(|e| Error::Crypto(e.to_string()))
}
