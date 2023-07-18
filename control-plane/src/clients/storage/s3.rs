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
    GetObject(#[from] SdkError<GetObjectError>),
    #[error("PutObject Error: {0}")]
    PutObject(#[from] SdkError<PutObjectError>),
    #[error("DeleteObject Error: {0}")]
    DeleteObject(#[from] SdkError<DeleteObjectError>),
    #[error("S3 Client Error - {0}")]
    General(String),
}

impl From<S3ClientError> for StorageClientError {
    fn from(error: S3ClientError) -> Self {
        match error {
            S3ClientError::GetObject(err) => StorageClientError::GetObject(err.to_string()),
            S3ClientError::PutObject(err) => StorageClientError::PutObject(err.to_string()),
            S3ClientError::DeleteObject(err) => StorageClientError::DeleteObject(err.to_string()),
            S3ClientError::General(err) => StorageClientError::General(err),
        }
    }
}

pub struct S3Client {
    bucket: String,
    client: s3::Client,
}

impl S3Client {
    #[allow(unused)]
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
            .await
            .map_err(S3ClientError::GetObject)?;

        let body = object
            .body
            .collect()
            .await
            .map_err(|err| S3ClientError::General(err.to_string()))?
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
            .await
            .map_err(S3ClientError::PutObject)?;

        Ok(())
    }

    async fn delete_object(&self, key: String) -> Result<(), StorageClientError> {
        let _ = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(S3ClientError::DeleteObject)?;

        Ok(())
    }
}
