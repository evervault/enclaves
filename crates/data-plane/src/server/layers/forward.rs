use hyper::client::Client;
use hyper::http::{header, Request, Response};
use hyper::{Body, Uri};
use shared::logging::TrxContextBuilder;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::net::TcpStream;
use tower::Service;

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

/// A hyper connector which always dials `127.0.0.1:<port>`.
/// All incoming traffic is forwarded from the data plane to the customer process.
#[derive(Clone)]
pub struct LoopbackConnector {
    addr: SocketAddr,
}

impl LoopbackConnector {
    pub fn new(port: u16) -> Self {
        Self {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        }
    }
}

impl Service<Uri> for LoopbackConnector {
    type Response = TcpStream;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let addr = self.addr;
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

#[derive(Clone)]
pub struct ForwardService {
    http_client: Client<LoopbackConnector, Body>,
}

impl ForwardService {
    pub fn new(customer_process_port: u16) -> Self {
        Self {
            http_client: Client::builder().build(LoopbackConnector::new(customer_process_port)),
        }
    }
}

impl Service<Request<Body>> for ForwardService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    // Service is always ready to receive requests
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let http_client = self.http_client.clone();
        Box::pin(async move {
            let context_builder = req
                .extensions_mut()
                .remove::<TrxContextBuilder>()
                .expect("No context set on received request");
            match http_client.request(req).await {
                Ok(mut response) => {
                    response.extensions_mut().insert(context_builder);
                    // Temporary fix: remove transfer encoding from response
                    if response
                        .headers_mut()
                        .remove(header::TRANSFER_ENCODING)
                        .is_some()
                    {
                        let (mut parts, body) = response.into_parts();
                        let body_bytes = hyper::body::to_bytes(body)
                            .await
                            .expect("Failed to read entire response body");
                        parts
                            .headers
                            .append("content-length", body_bytes.len().into());
                        return Ok(Response::from_parts(parts, Body::from(body_bytes)));
                    }
                    Ok(response)
                }
                Err(e) => {
                    let mut error_response: Response<Body> = ForwardError::from(e).into();
                    error_response.extensions_mut().insert(context_builder);
                    Ok(error_response)
                }
            }
        })
    }
}
