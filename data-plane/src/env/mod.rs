use crate::{base_tls_client::ClientError, ContextError};
use crate::{
    cert_provisioner_client::CertProvisionerClient,
    config_client::ConfigClient,
    e3client::{CryptoRequest, CryptoResponse, E3Api, E3Client},
    error::Error,
    EnclaveContext,
};
use hyper::header::InvalidHeaderValue;
use serde_json::json;
use shared::server::config_server::requests::{GetSecretsResponseDataPlane, Secret};
use std::{fs::File, future::Future, io::Write};
use std::{fs::OpenOptions, marker::PhantomData};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
    #[error("Deserialization Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Client error — {0}")]
    ClientError(#[from] ClientError),
    #[error("Could not create header value — {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("Failed to read context - {0}")]
    ContextError(#[from] ContextError),
}

/// Empty trait to enforce correctness in the Environment Loader — an Environment Loader can only wrap a known phase
/// which will expose the appropriate loader functions.
pub trait EnvLoadingPhaseMarker {}

/// Phase for loading the Enclaves environment variables, decrypting them, and exposing them in the customer-env file.
pub struct NeedEnv;
impl EnvLoadingPhaseMarker for NeedEnv {}

impl NeedEnv {
    async fn decrypt_secrets(
        loader: &EnvironmentLoader<Self>,
        secrets: Vec<Secret>,
    ) -> Result<Vec<Secret>, Error> {
        let (encrypted_env, plaintext_env): (_, Vec<Secret>) = secrets
            .into_iter()
            .partition(|env| env.secret.starts_with("ev:"));

        let mut plaintext_env = plaintext_env;

        if encrypted_env.is_empty() {
            return Ok(plaintext_env);
        }

        let e3_response: CryptoResponse = loader
            .e3_client
            .decrypt(CryptoRequest {
                data: json!(encrypted_env.clone()),
            })
            .await?;
        let mut decrypted_env: Vec<Secret> = serde_json::from_value(e3_response.data)?;
        decrypted_env.append(&mut plaintext_env);
        Ok(decrypted_env)
    }

    fn write_env_file(secrets: Vec<Secret>) -> Result<(), EnvError> {
        let mut file = File::create("/etc/customer-env")?;

        let env_string = secrets
            .iter()
            .map(|env| format!("export {}={}  ", env.name, env.secret))
            .collect::<Vec<String>>()
            .join("");

        file.write_all(env_string.as_bytes())?;
        Ok(())
    }

    async fn get_env(
        loader: &EnvironmentLoader<Self>,
    ) -> Result<GetSecretsResponseDataPlane, Error> {
        let half_min = 1_000 * 30;
        let cert_token = with_retries(500, 10, half_min, || async {
            loader.config_client.get_cert_token().await
        })
        .await?;

        let token = cert_token.token();
        let secrets_response = with_retries(500, 10, half_min, || async {
            loader
                .cert_provisioner_client
                .get_secrets(token.clone())
                .await
                .map_err(crate::error::Error::from)
        })
        .await?;

        Ok(secrets_response)
    }
}

/// Phase for marking the environment as ready and unblocking the customer process' start up script.
pub struct Finalize;
impl EnvLoadingPhaseMarker for Finalize {}

pub struct EnvironmentLoader<P> {
    phase: PhantomData<P>,
    cert_provisioner_client: CertProvisionerClient,
    config_client: ConfigClient,
    e3_client: E3Client,
}

#[cfg(feature = "tls_termination")]
mod tls_enabled {
    use super::*;
    use openssl::{
        pkey::{PKey, Private},
        x509::X509,
    };

    /// Phase for loading the intermediate CA details from the provisioner
    pub struct NeedCert;
    impl EnvLoadingPhaseMarker for NeedCert {}

    impl EnvironmentLoader<NeedEnv> {
        /// Load the environment variables from the provisioner and transition to the next appropriate loading state - `NeedCert`
        pub async fn load_env_vars(self) -> Result<EnvironmentLoader<NeedCert>, Error> {
            let GetSecretsResponseDataPlane { secrets, context } = NeedEnv::get_env(&self).await?;

            EnclaveContext::set(context.into());

            let customer_env = NeedEnv::decrypt_secrets(&self, secrets).await?;

            NeedEnv::write_env_file(customer_env)?;

            Ok(EnvironmentLoader {
                phase: PhantomData,
                cert_provisioner_client: self.cert_provisioner_client,
                config_client: self.config_client,
                e3_client: self.e3_client,
            })
        }
    }

    impl EnvironmentLoader<NeedCert> {
        /// Load the intermediate CA details from the provisioner, returning them alongside the loader in the `Finalize` state.
        pub async fn load_cert(
            self,
        ) -> Result<(EnvironmentLoader<Finalize>, X509, PKey<Private>), Error> {
            let half_min = 1_000 * 30;
            let cert_token = with_retries(100, 8, half_min, || async {
                self.config_client.get_cert_token().await
            })
            .await?;

            let token = cert_token.token();
            let cert_response = with_retries(100, 8, half_min, || async {
                self.cert_provisioner_client
                    .get_cert(token.clone())
                    .await
                    .map_err(|err| Error::CertServer(err.to_string()))
            })
            .await?;

            let inter_ca_cert = parse_cert(cert_response.cert())?;
            let inter_ca_key_pair = parse_key(cert_response.key_pair())?;
            Ok((
                EnvironmentLoader {
                    phase: PhantomData,
                    cert_provisioner_client: self.cert_provisioner_client,
                    config_client: self.config_client,
                    e3_client: self.e3_client,
                },
                inter_ca_cert,
                inter_ca_key_pair,
            ))
        }
    }

    fn parse_cert(raw_cert: String) -> Result<X509, Error> {
        let decoded_cert =
            base64::decode(raw_cert).map_err(|err| Error::Crypto(err.to_string()))?;
        X509::from_pem(&decoded_cert).map_err(|err| Error::Crypto(err.to_string()))
    }

    fn parse_key(raw_key: String) -> Result<PKey<Private>, Error> {
        let decoded_key = base64::decode(raw_key).map_err(|err| Error::Crypto(err.to_string()))?;
        PKey::private_key_from_pem(&decoded_key).map_err(|err| Error::Crypto(err.to_string()))
    }
}
#[cfg(feature = "tls_termination")]
pub use tls_enabled::*;

#[cfg(not(feature = "tls_termination"))]
mod tls_disabled {
    use super::*;

    impl EnvironmentLoader<NeedEnv> {
        /// Load the environment variables from the provisioner and transition to the next appropriate loading state - `Finalize`
        pub async fn load_env_vars(self) -> Result<EnvironmentLoader<Finalize>, Error> {
            let GetSecretsResponseDataPlane { secrets, context } = NeedEnv::get_env(&self).await?;

            EnclaveContext::set(context.into());

            let customer_env = NeedEnv::decrypt_secrets(&self, secrets).await?;

            NeedEnv::write_env_file(customer_env)?;

            Ok(EnvironmentLoader {
                phase: PhantomData,
                cert_provisioner_client: self.cert_provisioner_client,
                config_client: self.config_client,
                e3_client: self.e3_client,
            })
        }
    }
}
#[cfg(not(feature = "tls_termination"))]
pub use tls_disabled::*;

impl EnvironmentLoader<Finalize> {
    pub fn finalize_env(self) -> Result<(), Error> {
        write_startup_complete_env_vars()?;
        Ok(())
    }
}

/// Get an environment variable loader in the default state - `NeedEnv`
/// This is the only way an EnvironmentLoader should be built. This constraint is enforced by leaving the attributes private.
pub fn init_environment_loader() -> EnvironmentLoader<NeedEnv> {
    EnvironmentLoader {
        phase: PhantomData,
        cert_provisioner_client: Default::default(),
        config_client: Default::default(),
        e3_client: Default::default(),
    }
}

async fn with_retries<F, Fut, T>(
    backoff: u64,
    n_attempts: u32,
    upper_bound: u64,
    func: F,
) -> Result<T, crate::error::Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, crate::error::Error>>,
{
    use rand::{thread_rng, Rng};

    let mut attempts = 0;
    loop {
        let computed_backoff = (2_u64.pow(attempts) * backoff) + thread_rng().gen_range(50..150);
        attempts += 1;
        match func().await {
            Ok(response) => return Ok(response),
            Err(e) if attempts < n_attempts => {
                log::error!("Request failed during environment init flow - {e:?}");
                let limited_backoff = std::cmp::min(upper_bound, computed_backoff);
                tokio::time::sleep(tokio::time::Duration::from_millis(limited_backoff)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn write_startup_complete_env_vars() -> Result<(), Error> {
    let mut file = OpenOptions::new().append(true).open("/etc/customer-env")?;

    write!(file, "export EV_INITIALIZED=true")?;

    Ok(())
}

#[cfg(test)]
mod test {
    #[tokio::test]
    async fn with_retries_redrives_requests_as_expected() {
        let responses = vec![
            Ok(()),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
        ];

        let ctr = std::sync::Arc::new(std::sync::Mutex::new(responses));
        let ctr_clone = ctr.clone();
        let fallable_func = || async {
            let mut ctr_lock = ctr.lock().unwrap();
            let value = (*ctr_lock).pop().unwrap();
            value
        };

        let result = super::with_retries(100, 3, 1_000, fallable_func).await;
        assert!(result.is_ok());
        let responses_lock = ctr_clone.lock().unwrap();
        assert!(responses_lock.is_empty());
    }

    #[tokio::test]
    async fn with_retries_redrives_requests_and_bubbles_errors() {
        let responses = vec![
            Ok(()),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
            Err(crate::error::Error::RequestTimeout(0)),
        ];

        let ctr = std::sync::Arc::new(std::sync::Mutex::new(responses));
        let ctr_clone = ctr.clone();
        let fallable_func = || async {
            let mut ctr_lock = ctr.lock().unwrap();
            let value = (*ctr_lock).pop().unwrap();
            value
        };

        let result = super::with_retries(100, 3, 1_000, fallable_func).await;
        assert!(result.is_err());
        let responses_lock = ctr_clone.lock().unwrap();
        assert_eq!(responses_lock.len(), 1);
    }
}
