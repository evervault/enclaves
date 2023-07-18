mod s3;

use async_trait::async_trait;
use thiserror::Error;


#[derive(Error, Debug)]
pub enum StorageClientError {
    #[error("GetObject Error: {0}")]
    GetObjectError(String),
    #[error("PutObject Error: {0}")]
    PutObjectError(String),
    #[error("DeleteObject Error: {0}")]
    DeleteObjectError(String),
    #[error("Storage Client Error - {0}")]
    GeneralClientError(String),
}

// Make generic so other storage backends can be used
#[async_trait]
pub trait StorageClientInterface {
    async fn get_object(&self, key: String) -> Result<Vec<u8>, StorageClientError>;
    async fn put_object(&self, key: String, body: Vec<u8>) -> Result<(), StorageClientError>;
    async fn delete_object(&self, key: String) -> Result<(), StorageClientError>;
}

