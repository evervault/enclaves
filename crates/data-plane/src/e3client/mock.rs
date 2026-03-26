use super::{AuthRequest, E3Api, E3Error, E3Payload};
use async_trait::async_trait;
use hyper::http::HeaderValue;
use mockall::mock;
use serde::de::DeserializeOwned;

mock! {
  #[derive(Debug, Clone)]
  pub E3TestClient {}

  #[async_trait]
  impl E3Api for E3TestClient {
    async fn decrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(&self, payload: P) -> Result<T, E3Error>;

    async fn encrypt<T: DeserializeOwned + 'static, P: E3Payload + Send + Sync + 'static>(
        &self,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error>;

    async fn authenticate(&self, api_key: &HeaderValue, payload: AuthRequest) -> Result<(), E3Error>;

    async fn decrypt_with_retries<T: DeserializeOwned + 'static, P: E3Payload + Clone + Send + Sync + 'static>(
        &self,
        retries: usize,
        payload: P,
    ) -> Result<T, E3Error>;

    async fn encrypt_with_retries<T: DeserializeOwned + 'static, P: E3Payload + Clone + Send + Sync + 'static>(
        &self,
        retries: usize,
        payload: P,
        data_role: Option<String>,
    ) -> Result<T, E3Error>;
  }
}
