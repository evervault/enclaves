use shared::storage::{StorageClientError, StorageClientInterface};

use async_trait::async_trait;
use mockall::mock;

mock! {
  #[derive(Debug, Clone)]
  pub StorageClientInterface {}
  #[async_trait]
  impl StorageClientInterface for StorageClientInterface {
      async fn get_object(&self, key: String) -> Result<Option<String>, StorageClientError>;
      async fn put_object(&self, key: String, body: String) -> Result<(), StorageClientError>;
      async fn delete_object(&self, key: String) -> Result<(), StorageClientError>;
  }
}
