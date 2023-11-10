use hyper::client::{Client, HttpConnector};
use hyper::http::{Request, Response};
use hyper::Body;
use shared::logging::TrxContextBuilder;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use thiserror::Error;
use tower::Service;

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
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            let mut http_client = HTTP_CLIENT.get_or_init(Client::new).clone();
            let context_builder = req
                .extensions_mut()
                .remove::<TrxContextBuilder>()
                .expect("No context set on received request");
            match http_client.call(req).await {
                Ok(mut response) => {
                    response.extensions_mut().insert(context_builder);
                    return Ok(response);
                }
                Err(e) => {
                    let mut error_response: Response<Body> = ForwardError::from(e).into();
                    error_response.extensions_mut().insert(context_builder);
                    return Ok(error_response);
                }
            };
        })
    }
}
