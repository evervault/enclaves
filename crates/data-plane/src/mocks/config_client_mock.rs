use async_trait::async_trait;
use error::Result;
use mockall::mock;
use shared::server::config_server::requests::GetClockSyncResponse;
use shared::server::config_server::requests::GetObjectResponse;

use crate::{config_client::StorageConfigClientInterface, error};

mock! {
  #[derive(Debug, Clone)]
  pub StorageConfigClientInterface {}

  #[async_trait]
  impl StorageConfigClientInterface for StorageConfigClientInterface {
      async fn get_object(&self, key: String) -> Result<Option<GetObjectResponse>>;
      async fn put_object(&self, key: String, object: String) -> Result<()>;
      async fn delete_object(&self, key: String) -> Result<()>;
      async fn get_time_from_host(&self) -> Result<GetClockSyncResponse>;
  }
}
