use crate::acme::{client::AcmeClientInterface, error::AcmeError};
use async_trait::async_trait;
use hyper::{Body, Response};
use mockall::mock;

mock! {
  #[derive(Debug, Clone)]
  pub AcmeClientInterface {}

  #[async_trait]
  impl AcmeClientInterface for AcmeClientInterface {
    async fn send(&self, request: hyper::Request<Body>) -> Result<Response<Body>, AcmeError>;
  }
}
