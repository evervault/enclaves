use async_trait::async_trait;
use mockall::mock;
use shared::server::config_server::requests::GetObjectResponse;

use crate::config_client::{StorageConfigClientInterface, ConfigClientError};

mock! {
  #[derive(Debug, Clone)]
  pub StorageConfigClientInterface {}

  #[async_trait]
  impl StorageConfigClientInterface for StorageConfigClientInterface {
      async fn get_object(&self, key: String) -> Result<Option<GetObjectResponse>, ConfigClientError>;
      async fn put_object(&self, key: String, object: String) -> Result<(), ConfigClientError>;
      async fn delete_object(&self, key: String) -> Result<(), ConfigClientError>;
  }
}
