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
    CageContext,
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
            .header("content-type", "appliction/json")
            .header("content-length", body.len())
            .body(body.into())
            .expect("Failed to build auth error to response")
    }
}

#[derive(Clone)]
pub struct AuthLayer<T: E3Api + Send + Sync + 'static> {
    e3_client: Arc<T>,
    context: Arc<CageContext>,
}

impl<T: E3Api + Send + Sync + 'static> AuthLayer<T> {
    pub fn new(e3_client: Arc<T>, context: Arc<CageContext>) -> Self {
        Self { e3_client, context }
    }
}

impl<S, T: E3Api + Send + Sync + 'static> Layer<S> for AuthLayer<T> {
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
pub struct AuthService<S, T: E3Api + Send + Sync + 'static> {
    e3_client: Arc<T>,
    context: Arc<CageContext>,
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
        let cage_context = self.context.clone();
        Box::pin(async move {
            let Some(api_key) = req.headers().get("api-key") else {
                let mut error_response: Response<Body> = AuthError::NoApiKeyGiven.into();
                if let Some(context) = req.extensions_mut().remove::<TrxContextBuilder>() {
                    error_response.extensions_mut().insert(context);
                }
                return Ok(error_response);
            };

            if let Err(err) = auth_request(api_key, cage_context, e3_client).await {
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
    C: std::ops::Deref<Target = CageContext>,
    T: E3Api + Send + Sync + 'static,
>(
    api_key: &HeaderValue,
    cage_context: C,
    e3_client: Arc<T>,
) -> Result<(), AuthError> {
    log::debug!("Authenticating request");
    let hashed_api_key = HeaderValue::from_bytes(&compute_base64_sha512(api_key.as_bytes()))?;

    let auth_payload = AuthRequest::from(cage_context);
    // matching on error to handle retry with alternative key
    let Err(err) = e3_client
        .authenticate(&hashed_api_key, auth_payload.clone())
        .await
    else {
        return Ok(());
    };

    match err {
        ClientError::FailedRequest(status) if status.as_u16() == 401 => {
            log::debug!("Failed to auth with scoped api key hash, attempting with app api key");
            let Err(err) = e3_client.authenticate(api_key, auth_payload).await else {
                return Ok(());
            };
            match err {
                ClientError::FailedRequest(status) if status.as_u16() == 401 => {
                    Err(AuthError::FailedToAuthenticateApiKey)
                }
                e => Err(e.into()),
            }
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
        let context = CageContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "cage_uuid".into(),
            "cage_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_auth_success_with_second_attempt() {
        let mut e3_test_client = MockE3TestClient::new();
        let api_key = HeaderValue::from_str("my-api-key").unwrap();
        e3_test_client
            .expect_authenticate()
            .times(2)
            .returning(|received_api_key, _| {
                // first request hashes the api key, second sends it in the clear
                if received_api_key.to_str().unwrap() == "my-api-key" {
                    Ok(())
                } else {
                    Err(ClientError::FailedRequest(
                        StatusCode::from_u16(401).unwrap(),
                    ))
                }
            });

        let context = CageContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "cage_uuid".into(),
            "cage_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_auth_receives_401_on_both_requests() {
        let mut e3_test_client = MockE3TestClient::new();
        let api_key = HeaderValue::from_str("my-api-key").unwrap();
        e3_test_client
            .expect_authenticate()
            .times(2)
            .returning(|_, _| {
                Err(ClientError::FailedRequest(
                    StatusCode::from_u16(401).unwrap(),
                ))
            });

        let context = CageContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "cage_uuid".into(),
            "cage_name".into(),
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

        let context = CageContext::new(
            "team_uuid".into(),
            "app_uuid".into(),
            "cage_uuid".into(),
            "cage_name".into(),
        );

        let result = auth_request(&api_key, &context, Arc::new(e3_test_client)).await;
        assert!(result.is_err());
        let returned_err = result.unwrap_err();
        assert!(matches!(
            AuthError::InternalError(ClientError::FailedRequest(
                StatusCode::from_u16(500).unwrap()
            )),
            returned_err
        ));
    }
}
