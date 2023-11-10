use hyper::client::{Client, HttpConnector};
use hyper::header::InvalidHeaderValue;
use hyper::http::{Request, Response};
use hyper::Body;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use thiserror::Error;
use tower::Service;

use crate::server::error::TlsError;

static HTTP_CLIENT: OnceLock<Client<HttpConnector, hyper::Body>> = OnceLock::new();

#[derive(Debug, Error)]
enum ForwardError {
    #[error("Failed to request user process - {0}")]
    FailedToRequestUserProcess(#[from] hyper::Error),
}

impl std::convert::From<ForwardError> for Response<Body> {
    fn from(value: ForwardError) -> Self {
        let error_response = serde_json::json!({
          "message": value.to_string()
        })
        .to_string();
        Response::builder()
            .status(500)
            .header("content-type", "application/json")
            .header("content-length", error_response.len())
            .body(Body::from(error_response))
            .expect("Infallible: hardcoded response")
    }
}

#[derive(Clone)]
pub struct ForwardService;

impl Service<Request<Body>> for ForwardService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    // Service is always ready to receive requests
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            let mut http_client = HTTP_CLIENT.get_or_init(Client::new).clone();

            match http_client.call(req).await {
                Ok(response) => return Ok(response),
                Err(e) => return Ok(ForwardError::from(e).into()),
            };
        })
    }
}
