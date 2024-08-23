use hyper::header::InvalidHeaderValue;
use hyper::http::{HeaderValue, Request, Response};
use hyper::Body;
use sha2::Digest;
use shared::logging::TrxContextBuilder;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tower::{Layer, Service};

use crate::base_tls_client::ClientError;
use crate::{
    e3client::{AuthRequest, E3Api},
    EnclaveContext,
};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("No api-key header present on request")]
    NoApiKeyGiven,
    #[error("Invalid api key provided")]
    FailedToAuthenticateApiKey,
    #[error("Failed to decode api key from header")]
    DecodingError(#[from] InvalidHeaderValue),
    #[error("Internal error when attempting to authenticate - {0}")]
    InternalError(#[from] ClientError),
}

impl AuthError {
    fn to_status(&self) -> u16 {
        match self {
            Self::InternalError(_) => 500,
            _ => 401,
        }
    }
}

impl std::convert::From<AuthError> for Response<Body> {
    fn from(err: AuthError) -> Self {
        let msg = err.to_string();
        let body = serde_json::json!({
          "message": msg
        })
        .to_string();
        Response::builder()
            .status(err.to_status())
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(body.into())
            .expect("Failed to build auth error to response")
    }
}

#[derive(Clone)]
pub struct AuthLayer<T: E3Api> {
    e3_client: Arc<T>,
    context: Arc<EnclaveContext>,
}

impl<T: E3Api> AuthLayer<T> {
    pub fn new(e3_client: Arc<T>, context: Arc<EnclaveContext>) -> Self {
        Self { e3_client, context }
    }
}

impl<S, T: E3Api> Layer<S> for AuthLayer<T> {
    type Service = AuthService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            e3_client: self.e3_client.clone(),
            context: self.context.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S, T: E3Api> {
    e3_client: Arc<T>,
    context: Arc<EnclaveContext>,
    inner: S,
}

impl<S, T> Service<Request<Body>> for AuthService<S, T>
where
    T: E3Api + Send + Sync + 'static,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    // Service is always ready to receive requests
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let e3_client = self.e3_client.clone();
        let enclave_context = self.context.clone();
        Box::pin(async move {
            let Some(api_key) = req.headers().get("api-key") else {
                let mut error_response: Response<Body> = AuthError::NoApiKeyGiven.into();
                if let Some(context) = req.extensions_mut().remove::<TrxContextBuilder>() {
                    error_response.extensions_mut().insert(context);
                }
                return Ok(error_response);
            };

            if let Err(err) = auth_request(api_key, enclave_context, e3_client).await {
                let mut error_response: Response<Body> = err.into();
                if let Some(context) = req.extensions_mut().remove::<TrxContextBuilder>() {
                    error_response.extensions_mut().insert(context);
                }
                return Ok(error_response);
            }

            inner.call(req).await
        })
    }
}

fn compute_base64_sha512(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(input.as_ref());
    let hash_digest = base64::encode(hasher.finalize().as_slice());
    hash_digest.as_bytes().to_vec()
}

pub async fn auth_request<
    C: std::ops::Deref<Target = EnclaveContext>,
    T: E3Api + Send + Sync + 'static,
>(
    api_key: &HeaderValue,
    enclave_context: C,
    e3_client: Arc<T>,
) -> Result<(), AuthError> {
    log::debug!("Authenticating request");
    let hashed_api_key = HeaderValue::from_bytes(&compute_base64_sha512(api_key.as_bytes()))?;

    let auth_payload = AuthRequest::from(enclave_context);
    // matching on error to handle retry with alternative key
    let Err(err) = e3_client
        .authenticate(&hashed_api_key, auth_payload.clone())
        .await
    else {
        return Ok(());
    };

    match err {
        ClientError::FailedRequest(status) if status.as_u16() == 401 => {
            log::debug!("Failed to auth with scoped api key hash");
            Err(AuthError::FailedToAuthenticateApiKey)
        }
        e => Err(e.into()),
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use hyper::StatusCode;

    use super::*;
    use crate::e3client::mock::MockE3TestClient;

    #[tokio::test]
    async fn test_request_auth_success_with_hashed_key() {
        let mut e3_test_client = MockE3TestClient::new();
        e3_test_client
            .expect_authenticate()
            .times(1)
            .returning(|_, _| Ok(()));

        let api_key = HeaderValue::from_str("my-api-key").unwrap();
        let context = EnclaveContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "enclave_uuid".into(),
            "enclave_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_auth_maps_401_to_correct_error() {
        let mut e3_test_client = MockE3TestClient::new();
        let api_key = HeaderValue::from_str("my-api-key").unwrap();
        e3_test_client
            .expect_authenticate()
            .times(1)
            .returning(|_, _| {
                Err(ClientError::FailedRequest(
                    StatusCode::from_u16(401).unwrap(),
                ))
            });

        let context = EnclaveContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "enclave_uuid".into(),
            "enclave_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_err());
        let auth_err = result.unwrap_err();
        assert!(matches!(auth_err, AuthError::FailedToAuthenticateApiKey));
    }

    #[tokio::test]
    async fn test_request_does_not_retry_on_internal_error() {
        let mut e3_test_client = MockE3TestClient::new();
        let api_key = HeaderValue::from_str("my-api-key").unwrap();
        e3_test_client
            .expect_authenticate()
            .times(1)
            .returning(|_, _| {
                Err(ClientError::FailedRequest(
                    StatusCode::from_u16(500).unwrap(),
                ))
            });

        let context = EnclaveContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "enclave_uuid".into(),
            "enclave_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_err());
        let _returned_err = result.unwrap_err();
        assert!(matches!(
            AuthError::InternalError(ClientError::FailedRequest(
                StatusCode::from_u16(500).unwrap()
            )),
            _returned_err
        ));
    }
}
