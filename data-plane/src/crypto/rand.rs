use crate::error::{Error, Result};

#[cfg(feature = "enclave")]
pub fn rand_bytes(buffer: &mut [u8]) -> Result<()> {
    use crate::utils::nsm::NsmConnection;
    use aws_nitro_enclaves_nsm_api as nitro;
    let nsm_conn = NsmConnection::try_new()?;
    match nitro::driver::nsm_process_request(nsm_conn.fd(), nitro::api::Request::GetRandom) {
        nitro::api::Response::GetRandom { random } => {
            buffer.copy_from_slice(&random);
            Ok(())
        }
        nitro::api::Response::Error(e) => Err(Error::Crypto(format!(
            "Could not get entropy from the Nitro Secure Module! {e:?}"
        ))),
        _ => Err(Error::Crypto(
            "Received unknown response from Nitro Secure Module".to_string(),
        )),
    }
}

#[cfg(not(feature = "enclave"))]
pub fn rand_bytes(buffer: &mut [u8]) -> Result<()> {
    openssl::rand::rand_bytes(buffer).map_err(|e| Error::Crypto(e.to_string()))
}
