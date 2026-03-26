#[cfg(feature = "s3")]
pub mod s3;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageClientError {
    #[error("GetObject Error: {0}")]
    GetObject(String),
    #[error("PutObject Error: {0}")]
    PutObject(String),
    #[error("DeleteObject Error: {0}")]
    DeleteObject(String),
    #[error("Storage Client Error - {0}")]
    General(String),
}

#[async_trait]
pub trait StorageClientInterface {
    async fn get_object(&self, key: String) -> Result<Option<String>, StorageClientError>;
    async fn put_object(&self, key: String, body: String) -> Result<(), StorageClientError>;
    async fn delete_object(&self, key: String) -> Result<(), StorageClientError>;
}
