use chrono::{Utc, DateTime, Duration};
use openssl::{x509::X509, pkey::{PKey, Private}};
use serde::{Deserialize, Serialize};
use serde_json::json;
use chrono::serde::ts_seconds;
use uuid::Uuid;
use tokio_rustls::rustls::{sign::{CertifiedKey, self}, PrivateKey, Certificate};

use crate::{e3client::{E3Client, CryptoRequest, CryptoResponse}, config_client::ConfigClient};

use self::{error::AcmeError, helpers::gen_ec_private_key, key::RawAcmeKeyPair};

pub mod account;
pub mod authorization;
pub mod client;
pub mod directory;
pub mod error;
pub mod helpers;
pub mod jws;
pub mod order;
pub mod lock;
pub mod key;

#[cfg(test)]
pub mod mocks;

// const CERT_OBJECT_KEY: &str = "cert.pem";
// const PUBLIC_KEY_OBJECT_KEY: &str = "public_key.pem";
// const PRIVATE_KEY_OBJECT_KEY: &str = "private_key.pem";
// const LOCK_TIME_SECONDS: u64 = 30;

// pub struct AcmeMaterials {
//     pub cert_chain: Vec<X509>,
//     pub key_pair: PKey<Private>
// }

// impl AcmeMaterials {

//     pub fn from_raw(raw_acme_materials: RawAcmeMaterials) -> Result<Self, AcmeError> {
//         let raw_cert = if raw_acme_materials.cert.is_none() {
//             return Err(AcmeError::General("No raw cert set in Acme Materials to convert to cert".into()));
//         } else {
//             raw_acme_materials.cert.expect("Infallible - checked")
//         };

//         let cert_chain: Vec<X509> = todo!();
//         let key_pair: PKey<Private> = todo!();

//         Ok(Self {
//             cert_chain,
//             key_pair
//         })
//     }


//     pub fn to_certified_key(&self) -> Result<CertifiedKey, AcmeError> {
//         let der_encoded_private_key = self.key_pair.private_key_to_der()?;
//         let ecdsa_private_key = sign::any_ecdsa_type(&PrivateKey(der_encoded_private_key))?;
//         let mut combined_pem_encoded_certs: Vec<Vec<u8>> = vec![];

//         for x509 in self.cert_chain {
//             let pem = x509.to_pem()?;
//             combined_pem_encoded_certs.push(pem);
//         }
//         let parsed_pems = pem::parse_many(combined_pem_encoded_certs.concat())?;
        
//         let cert_chain: Vec<Certificate> = parsed_pems
//             .into_iter()
//             .map(|p| Certificate(p.contents))
//             .collect();
        
//         let cert_and_key = CertifiedKey::new(cert_chain, ecdsa_private_key);

//         Ok(cert_and_key)
//     }
// }

// #[derive(Debug, Clone, Deserialize, Serialize)]
// struct RawAcmeMaterials {
//     //Cert might not exist but key pair created
//     pub cert: Option<String>,
//     pub raw_acme_key_pair: RawAcmeKeyPair,
// }

// impl RawAcmeMaterials {

//     pub fn get_key_pair(&self) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, AcmeError> {
//         let private_key = openssl::pkey::PKey::private_key_from_pem(self.raw_acme_key_pair.private_key.as_bytes())?;
//         Ok(private_key)
//     }

//     pub fn generate_with_new_key_pair() -> Result<Self, AcmeError> {
//         let ec_key_pair = gen_ec_private_key()?;
//         Self::from_key_pair(ec_key_pair)
//     }

//     pub fn from_key_pair(key_pair: PKey<Private>) -> Result<Self, AcmeError> {
//         let raw_acme_key_pair = RawAcmeKeyPair::from_key_pair(key_pair)?;

//         let cert_materials = Self {
//             cert: None,
//             raw_acme_key_pair
//         };

//         Ok(cert_materials)
//     }

//     pub fn to_certified_key(&self) -> Result<CertifiedKey, AcmeError> {
//         let key_pair = self.get_key_pair()?;
//         let cert_materials = AcmeMaterials::from_raw(self.clone())?;
//         cert_materials.to_certified_key()
//     }
// }

// pub struct TrustedCertRetriever {
//     pub config_client: ConfigClient,
//     pub e3_client: E3Client, 
// }

// impl TrustedCertRetriever {
//     pub fn new(config_client: ConfigClient, e3_client: E3Client) -> Self {
//         Self {
//             config_client,
//             e3_client,
//         }
//     }

//     pub async fn get_or_order_cert(&self) -> Result<CertifiedKey, AcmeError> {
//         let raw_acme_materials = self.retrieve_raw_acme_materials().await?;

//         match raw_acme_materials.clone().cert {
//             Some(cert) => {
//                 let certified_key = raw_acme_materials.to_certified_key();
//                 return certified_key
//             },
//             None => {
//                 let order_lock = self.get_order_lock().await?;
                
//                 if let Some(lock) = order_lock {
//                     if lock.is_expired() {
//                         self.create_and_store_order_lock().await?;
//                     } else {
//                         return Err(AcmeError::General("Order lock exists and is not expired".into()));
//                     }
//                 } else {
//                     self.create_and_store_order_lock().await?;
//                 }
//                 // Check for order lock
//                 // - Exists ---- Check if valid
//                 // - Doesn't ---- Create order lock
//                 // - 
//             }
//         }
//         Ok(())
//     } 

//     async fn poll_for_cert_or_lock_timeout(&self, lock_expiry_time: DateTime<Utc>) -> Result<(Option<CertifiedKey>, bool), AcmeError> {
//         let mut res: Option<CertifiedKey> = None; 
//         let raw_acme_materials = self.retrieve_raw_acme_materials().await?;

//         let mut i = 0;

//         while res.is_none() {

//             // Try retrieve cert for 30 seconds
//             if i > 6 {
//                 return Ok(None, true);
//             };

//             match raw_acme_materials.clone().cert {
//                 Some(cert) => {
//                     let certified_key = raw_acme_materials.to_certified_key();
//                     res = Some(certified_key).transpose()?;
//                 },
//                 None => {
//                     res = None;
//                     i += 1;
//                     tokio::time::sleep(std::time::Duration::from_secs(5)).await;
//                 }
//             }
//         }

//         return Ok(res, true);
//     }


//     async fn retrieve_raw_acme_materials(&self) -> Result<RawAcmeMaterials, AcmeError> {
//         let encrypted_cert = self.config_client.get_object(CERT_OBJECT_KEY.to_owned()).await?.map(|response| response.body());
//         let encrypted_public_key = self.config_client.get_object(PUBLIC_KEY_OBJECT_KEY.to_owned()).await?.body();
//         let encrypted_private_key = self.config_client.get_object(PRIVATE_KEY_OBJECT_KEY.to_owned()).await?.body();

//         let encrypted_acme_materials = RawAcmeMaterials {
//             cert: encrypted_cert,
//             public_key: encrypted_public_key,
//             private_key: encrypted_private_key,
//         };

//         let decrypted_acme_materials = self.decrypt_acme_materials(encrypted_acme_materials).await?;

//         Ok(decrypted_acme_materials)
//     }

//     async fn create_and_store_order_lock(&self) -> Result<(), AcmeError> {
//         let order_lock = StorageLock::new();
//         self.config_client.put_object("order_lock".into(), order_lock.to_string()).await.map_err(AcmeError::ConfigClient)
//     }

//     async fn get_order_lock(&self) -> Result<Option<OrderLock>, AcmeError> {
//         let order_lock_response = self.config_client.get_object("order_lock".into()).await?;
//         if let Some(order_lock_string) = order_lock_response {
//             let order_lock = StorageLock::from_string(&order_lock_string.body())?;
//             Ok(Some(order_lock))
//         } else {
//             Ok(None)
//         }
//     }

//     async fn decrypt_acme_materials(&self, encrypted_acme_materials: RawAcmeMaterials) -> Result<RawAcmeMaterials, AcmeError> {
//         let e3_response: CryptoResponse = self
//             .e3_client
//             .decrypt(CryptoRequest {
//                 data: json!(encrypted_acme_materials),
//             })
//             .await?;

//         let decrypted_acme_materials: RawAcmeMaterials = serde_json::from_value(e3_response.data)?;

//         Ok(decrypted_acme_materials)
//     }

//     async fn encrypt_acme_materials(&self, acme_materials: RawAcmeMaterials) -> Result<RawAcmeMaterials, AcmeError> {
//         let e3_response: CryptoResponse = self
//             .e3_client
//             .encrypt(CryptoRequest {
//                 data: json!(acme_materials),
//             })
//             .await?;

//         let encrypted_acme_materials: RawAcmeMaterials = serde_json::from_value(e3_response.data)?;

//         Ok(encrypted_acme_materials)
//     }
// }





