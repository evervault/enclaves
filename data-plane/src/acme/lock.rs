use chrono::{DateTime, Utc, serde::ts_seconds, Duration};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_client::ConfigClient;

use super::error::AcmeError;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageLock {
    #[serde(skip)]
    config_client: ConfigClient,
    pub name: String,
    pub uuid: String,
    #[serde(with = "ts_seconds")]
    expiry_time: DateTime<Utc>
}

impl StorageLock {
    pub fn new(name: String) -> Self {
        let uuid = Uuid::new_v4().to_string();
        Self {
            config_client: ConfigClient::new(),
            name,
            uuid,
            expiry_time: Utc::now() + Duration::seconds(30)
        }
    }
    pub fn new_with_config_client(name: String, config_client: ConfigClient) -> Self {
        let uuid = Uuid::new_v4().to_string();
        Self {
            config_client,
            name,
            uuid,
            expiry_time: Utc::now() + Duration::seconds(30)
        }
    }

    pub async fn read_from_storage(name: String) -> Result<Option<Self>, AcmeError> {
        let config_client = ConfigClient::new();
        let get_lock_response = config_client.get_object(format!("{}.lock", name)).await?;
        match get_lock_response{
            Some(response) => {
                let mut lock: StorageLock = serde_json::from_str(&response.body())?;
                lock.config_client = config_client;
                Ok(Some(lock))
            },
            None => Ok(None)
        }
    }
    
    fn lock_key_name(&self) -> String {
        format!("{}.lock", self.name)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiry_time
    }

    pub fn has_uuid(&self, uuid: String) -> bool {
        self.uuid == uuid
    }

    pub async fn write_lock(&self) -> Result<(), AcmeError> {
        let lock = serde_json::to_string(self)?;
        self.config_client.put_object(self.lock_key_name(), lock).await?;
        Ok(())
    }

    pub async fn is_persisted(&self) -> Result<bool, AcmeError> {
        let persisted_lock_maybe_response = self.config_client.get_object(self.lock_key_name()).await?;
        match persisted_lock_maybe_response {
            Some(response) => {
                let lock: Self = serde_json::from_str(&response.body())?;
                Ok(lock.has_uuid(self.uuid.clone()))
            },
            None => Ok(false)
        }
    }

    pub async fn write_and_check_persisted(&self) -> Result<bool, AcmeError> {
        self.write_lock().await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        self.is_persisted().await
    }

    pub async fn delete(&self) -> Result<(), AcmeError> {
        self.config_client.delete_object(self.lock_key_name()).await?;
        Ok(())
    }
}