use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3 as s3;
use s3::{
    error::SdkError,
    operation::{
        delete_object::DeleteObjectError, get_object::GetObjectError, put_object::PutObjectError,
    },
    primitives::ByteStream,
    Client,
};
use thiserror::Error;

use super::{StorageClientError, StorageClientInterface};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("GetObject Error: {0}")]
    GetObject(#[from] SdkError<GetObjectError>),
    #[error("PutObject Error: {0}")]
    PutObject(#[from] SdkError<PutObjectError>),
    #[error("DeleteObject Error: {0}")]
    DeleteObject(#[from] SdkError<DeleteObjectError>),
    #[error("S3 Client Error - {0}")]
    General(String),
}

impl From<ClientError> for StorageClientError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::GetObject(err) => StorageClientError::GetObject(err.to_string()),
            ClientError::PutObject(err) => StorageClientError::PutObject(err.to_string()),
            ClientError::DeleteObject(err) => StorageClientError::DeleteObject(err.to_string()),
            ClientError::General(err) => StorageClientError::General(err),
        }
    }
}
#[derive(Clone, Debug)]
pub struct StorageClient {
    bucket: String,
    client: s3::Client,
}

impl StorageClient {
    #[allow(unused)]
    pub async fn new(bucket: String) -> Self {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::from_env().region(region_provider).load().await;
        let client = Client::new(&config);
        Self { bucket, client }
    }
}

#[async_trait]
impl StorageClientInterface for StorageClient {
    async fn get_object(&self, key: String) -> Result<Option<String>, StorageClientError> {
        let object_res = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;

        let object = match object_res {
            Ok(object) => object,
            Err(err) => match err.into_service_error() {
                GetObjectError::NoSuchKey(_) => return Ok(None),
                err => {
                    println!("Error getting object from S3: {:?}", err);
                    return Err(StorageClientError::GetObject(err.to_string()));
                }
            },
        };

        let body_bytes = object
            .body
            .collect()
            .await
            .map_err(|err| ClientError::General(err.to_string()))?
            .to_vec();

        let body = String::from_utf8(body_bytes)
            .map_err(|err| ClientError::General(format!("Failed to parse object body: {err}")))?;

        Ok(Some(body))
    }

    async fn put_object(&self, key: String, body: String) -> Result<(), StorageClientError> {
        let body_bytes = body.as_bytes().to_vec();

        let _ = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body_bytes))
            .send()
            .await
            .map_err(|err| {
                println!("Error puttin object to S3: {:?}", err);
                ClientError::PutObject(err)
            })?;

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
            .map_err(|err| {
                println!("Error deleting object in S3: {:?}", err);
                ClientError::DeleteObject(err)
            })?;

        Ok(())
    }
}
