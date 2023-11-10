use hyper::header::InvalidHeaderValue;
use hyper::http::{HeaderValue, Request, Response};
use hyper::Body;
use sha2::Digest;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tower::{Layer, Service};

use crate::base_tls_client::ClientError;
use crate::{
    e3client::{AuthRequest, E3Client},
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
            .header("content-length", msg.len())
            .body(body.into())
            .expect("Failed to build auth error to response")
    }
}

pub struct AuthLayer {
    e3_client: Arc<E3Client>,
    context: Arc<CageContext>,
}

impl AuthLayer {
    pub fn new(e3_client: Arc<E3Client>, context: Arc<CageContext>) -> Self {
        Self { e3_client, context }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            e3_client: self.e3_client.clone(),
            context: self.context.clone(),
            inner,
        }
    }
}

pub struct AuthService<S> {
    e3_client: Arc<E3Client>,
    context: Arc<CageContext>,
    inner: S,
}

impl<S> Service<Request<Body>> for AuthService<S>
where
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

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let e3_client = self.e3_client.clone();
        let cage_context = self.context.clone();
        Box::pin(async move {
            let Some(api_key) = req.headers().get("api-key") else {
              return Ok(AuthError::NoApiKeyGiven.into());
            };

            if let Err(err) = auth_request(api_key, cage_context, e3_client).await {
                return Ok(AuthError::FailedToAuthenticateApiKey.into());
            }

            return inner.call(req).await;
        })
    }
}

fn compute_base64_sha512(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(input.as_ref());
    let hash_digest = base64::encode(hasher.finalize().as_slice());
    hash_digest.as_bytes().to_vec()
}

async fn auth_request<C: std::ops::Deref<Target = CageContext>>(
    api_key: &HeaderValue,
    cage_context: C,
    e3_client: Arc<E3Client>,
) -> Result<(), AuthError> {
    log::debug!("Authenticating request");
    let hashed_api_key = HeaderValue::from_bytes(&compute_base64_sha512(api_key.as_bytes()))?;

    let auth_payload = AuthRequest::from(cage_context);
    // matching on error to handle retry with alternative key
    let Err(err) = e3_client.authenticate(&hashed_api_key, auth_payload.clone()).await else {
      return Ok(());
    };

    match err {
        ClientError::FailedRequest(status) if status.as_u16() == 401 => {
            log::debug!("Failed to auth with scoped api key hash, attempting with app api key");
            let Err(err) = e3_client.authenticate(&api_key, auth_payload).await else { return Ok(()) };
            match err {
                ClientError::FailedRequest(status) if status.as_u16() == 401 => {
                    return Err(AuthError::FailedToAuthenticateApiKey);
                }
                e => return Err(e.into()),
            }
        }
        e => return Err(e.into()),
    }
}
