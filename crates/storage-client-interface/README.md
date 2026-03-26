# storage-client-interface

The StorageClientInterface is a trait that defines a set of methods for interacting with object storage. It provides a clear and standardized way to perform common operations for retrieving, uploading, and deleting objects from a storage service. An S3 implementation is also provided under the feature `s3` which is included under the `default` feature.

## Trait Definition

```rust
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
```

## Methods

### get_object

Retrieves an object from the storage service based on the provided key.

```rust
async fn get_object(&self, key: String) -> Result<Option<String>, StorageClientError>;
```

### put_object

Uploads an object to the storage service with the given key and body.

```rust
async fn put_object(&self, key: String, body: String) -> Result<(), StorageClientError>;
```

### delete_object

Deletes an object from the storage service using the specified key.

```rust
async fn delete_object(&self, key: String) -> Result<(), StorageClientError>;
```
