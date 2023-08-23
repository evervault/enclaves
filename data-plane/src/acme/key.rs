use openssl::pkey::{Private, PKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{config_client::ConfigClient, e3client::{E3Client, CryptoResponse, CryptoRequest}};

use super::{error::AcmeError, helpers::gen_ec_private_key, lock::StorageLock};

const KEY_PAIR_LOCK_NAME: &str = "keypair";

//Used for encrypting and storing the key pair for the public cert
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawAcmeKeyPair {
    pub public_key: String,
    pub private_key: String,   
}

const PUBLIC_KEY_OBJECT_KEY: &str = "public_key.pem";
const PRIVATE_KEY_OBJECT_KEY: &str = "private_key.pem";

impl RawAcmeKeyPair {
    
    pub fn key_pair(&self) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, AcmeError> {
        let key_pair = openssl::pkey::PKey::private_key_from_pem(self.private_key.as_bytes())?;
        Ok(key_pair)
    }

    pub fn generate_with_new_key_pair() -> Result<Self, AcmeError> {
        let ec_key_pair = gen_ec_private_key()?;
        Self::from_key_pair(ec_key_pair)
    }

    pub fn from_key_pair(key_pair: PKey<Private>) -> Result<Self, AcmeError> {
        let public_key_bytes = key_pair.public_key_to_pem()?;
        let private_key_bytes = key_pair.private_key_to_pem_pkcs8()?;

        let public_key_string = String::from_utf8(public_key_bytes)?;
        let private_key_string = String::from_utf8(private_key_bytes)?;

        let cert_materials = Self {
            public_key: public_key_string,
            private_key: private_key_string,
        };

        Ok(cert_materials)
    }

    pub async fn from_storage(config_client: ConfigClient) -> Result<Option<Self>, AcmeError> {
        let public_key = config_client.get_object(PUBLIC_KEY_OBJECT_KEY.into()).await?;
        let private_key = config_client.get_object(PRIVATE_KEY_OBJECT_KEY.into()).await?;

        match (public_key, private_key) {
            (Some(public_key_res), Some(private_key_res)) => {
                let raw_acme_key_pair = Self {
                    public_key: public_key_res.body(),
                    private_key: private_key_res.body(),
                };
                Ok(Some(raw_acme_key_pair))
            },
            _ => Ok(None)
        }
    }

    pub async fn persist(&self, config_client: ConfigClient) -> Result<(), AcmeError> {
        config_client.put_object(PUBLIC_KEY_OBJECT_KEY.into(), self.public_key.clone()).await?;
        config_client.put_object(PRIVATE_KEY_OBJECT_KEY.into(), self.private_key.clone()).await?;
        Ok(())
    }

}

pub struct AcmeKeyRetreiver {
    pub config_client: ConfigClient,
    pub e3_client: E3Client,
}

impl AcmeKeyRetreiver {
    
    pub fn new(config_client: ConfigClient, e3_client: E3Client) -> Self {
        Self {
            config_client,
            e3_client,
        }
    }

    pub async fn get_or_create_cage_key_pair(&self) -> Result<PKey<Private>, AcmeError> {

        println!("Starting polling for ACME key pair");
        let mut persisted_key_pair: Option<PKey<Private>> = None;

        let max_checks = 5;
        let mut i = 0;

        while persisted_key_pair.is_none() {
            i += 1;

            if i >= max_checks {
                return Err(AcmeError::General("Max retries for getting ".into()));
            }

            match RawAcmeKeyPair::from_storage(self.config_client.clone()).await? {
                Some(raw_acme_key_pair) => {
                    println!("Key pair found in storage");
                    //Key pair already exists, decrypt it
                    let decrypted_key_pair = Self::decrypt_key_pair(self.e3_client.clone(), raw_acme_key_pair).await?;
                    persisted_key_pair = Some(decrypted_key_pair.key_pair()?);
                },
                None => {
                    println!("Key pair not found in storage, checking for lock");
                    let existing_lock = StorageLock::read_from_storage(KEY_PAIR_LOCK_NAME.into()).await?;
                    match existing_lock {
                        Some(lock) => {
                            println!("Lock found, checking if expired");
                            if lock.is_expired() {
                                println!("Lock expired, creating new lock, creating key pair, encrypting key pair, persisting key pair, deleting lock");
                                //Lock is expired - create new lock, create_key_pair - encrypt key pair - persist key pair - delete lock
                                let  unencrypted_key_pair_maybe = self.create_key_pair_and_persist_with_lock().await?;
                                persisted_key_pair = unencrypted_key_pair_maybe;
                            }
                            println!("Lock not expired, waiting for key pair to be created by other instance or waiting for lock to expire");
                            //Do nothing if Lock is not expired
                            //wait for key pair to be created by other instance or wait for lock to expire
                            
                        },
                        None => {
                            println!("Lock not found, creating lock, creating key pair, encrypting key pair, persisting key pair, deleting lock");
                            //Lock doesn't exist - create lock - create_key_pair - encrypt key pair - persist key pair - delete lock
                            let unencrypted_key_pair_maybe = self.create_key_pair_and_persist_with_lock().await?;
                            persisted_key_pair = unencrypted_key_pair_maybe;
                        }
                    }
                }
            };

            if persisted_key_pair.is_none() {
                println!("Key pair not found, sleeping for 3 seconds");
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }

        if let Some(persisted_key_pair) = persisted_key_pair {
            println!("Key pair found after polling");
            return Ok(persisted_key_pair);
        } else {
            return Err(AcmeError::General("Key pair not found after polling".into()));
        }
    }

    async fn create_key_pair_and_persist_with_lock(&self) ->  Result<Option<PKey<Private>>, AcmeError> {
        let key_pair_lock = StorageLock::new_with_config_client(KEY_PAIR_LOCK_NAME.into(), self.config_client.clone());
        if key_pair_lock.write_and_check_persisted().await? {
            let raw_acme_key_pair = RawAcmeKeyPair::generate_with_new_key_pair()?;
            let encrypted_key_pair = Self::encrypt_key_pair(self.e3_client.clone(), raw_acme_key_pair.clone()).await?;
            encrypted_key_pair.persist(self.config_client.clone()).await?;
            key_pair_lock.delete().await?;
            Ok(Some(raw_acme_key_pair.key_pair()?))
        } else {
            Ok(None)
        }
    }

    async fn decrypt_key_pair(e3_client: E3Client, encrypted_raw_acme_key_pair: RawAcmeKeyPair) -> Result<RawAcmeKeyPair, AcmeError> {
        let e3_response: CryptoResponse = e3_client
            .decrypt(CryptoRequest {
                data: json!(encrypted_raw_acme_key_pair),
            })
            .await?;

        let decrypted_acme_key_pair: RawAcmeKeyPair = serde_json::from_value(e3_response.data)?;

        Ok(decrypted_acme_key_pair)
    }

    async fn encrypt_key_pair(e3_client: E3Client, raw_acme_key_pair: RawAcmeKeyPair) -> Result<RawAcmeKeyPair, AcmeError> {
        let e3_response: CryptoResponse = e3_client
            .encrypt(CryptoRequest {
                data: json!(raw_acme_key_pair),
            })
            .await?;

        let encrypted_acme_key_pair: RawAcmeKeyPair = serde_json::from_value(e3_response.data)?;

        Ok(encrypted_acme_key_pair)
    }
}




