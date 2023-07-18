use async_trait::async_trait;
use aws_sdk_s3 as s3;
use s3::{
    error::SdkError,
    operation::{
        delete_object::DeleteObjectError, get_object::GetObjectError, put_object::PutObjectError,
    },
    primitives::ByteStream,
};
use thiserror::Error;

use super::{StorageClientError, StorageClientInterface};

#[derive(Error, Debug)]
pub enum S3ClientError {
    #[error("GetObject Error: {0}")]
    GetObjectError(#[from] SdkError<GetObjectError>),
    #[error("PutObject Error: {0}")]
    PutObjectError(#[from] SdkError<PutObjectError>),
    #[error("DeleteObject Error: {0}")]
    DeleteObjectError(#[from] SdkError<DeleteObjectError>),
    #[error("S3 Client Error - {0}")]
    GeneralClientError(String),
}

impl From<S3ClientError> for StorageClientError {
    fn from(error: S3ClientError) -> Self {
        match error {
            S3ClientError::GetObjectError(err) => StorageClientError::GetObjectError(err.to_string()),
            S3ClientError::PutObjectError(err) => StorageClientError::PutObjectError(err.to_string()), 
            S3ClientError::DeleteObjectError(err) => StorageClientError::DeleteObjectError(err.to_string()),
            S3ClientError::GeneralClientError(err) => StorageClientError::GeneralClientError(err),
        }
    }
}

pub struct S3Client {
    bucket: String,
    client: s3::Client,
}

impl S3Client {
    pub async fn new(bucket: String) -> Self {
        let config = aws_config::load_from_env().await;
        let client = s3::Client::new(&config);
        Self { bucket, client }
    }
}

#[async_trait]
impl StorageClientInterface for S3Client {
    
    async fn get_object(&self, key: String) -> Result<Vec<u8>, StorageClientError> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await.map_err(S3ClientError::GetObjectError)?;

        let body = object
            .body
            .collect()
            .await
            .map_err(|err| StorageClientError::GeneralClientError(err.to_string()))?
            .to_vec();

        Ok(body)
    }

    async fn put_object(&self, key: String, body: Vec<u8>) -> Result<(), StorageClientError> {
        let _ = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await.map_err(S3ClientError::PutObjectError)?;

        Ok(())
    }

    async fn delete_object(&self, key: String) -> Result<(), StorageClientError> {
        let _ = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await.map_err(S3ClientError::DeleteObjectError)?;

        Ok(())
    }
}


