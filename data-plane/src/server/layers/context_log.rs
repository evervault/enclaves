use crate::server::http::RemoteIp;
use crate::utils::trx_handler::LogHandlerMessage;
use crate::EnclaveContext;
use crate::FeatureContext;
use hyper::http::{Request, Response};
use hyper::{Body, HeaderMap};
use shared::logging::{RequestType, TrxContextBuilder};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct ContextLogLayer {
    context: Arc<EnclaveContext>,
    feature_context: Arc<FeatureContext>,
    tx_sender: UnboundedSender<LogHandlerMessage>,
}

impl ContextLogLayer {
    pub fn new(
        context: Arc<EnclaveContext>,
        feature_context: Arc<FeatureContext>,
        tx_sender: UnboundedSender<LogHandlerMessage>,
    ) -> Self {
        Self {
            context,
            feature_context,
            tx_sender,
        }
    }
}

impl<S> Layer<S> for ContextLogLayer {
    type Service = ContextLogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ContextLogService {
            context: self.context.clone(),
            feature_context: self.feature_context.clone(),
            tx_sender: self.tx_sender.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct ContextLogService<S> {
    context: Arc<EnclaveContext>,
    feature_context: Arc<FeatureContext>,
    tx_sender: UnboundedSender<LogHandlerMessage>,
    inner: S,
}

impl<S> Service<Request<Body>> for ContextLogService<S>
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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let enclave_context = self.context.clone();
        let feature_context = self.feature_context.clone();
        let log_tx_sender = self.tx_sender.clone();
        Box::pin(async move {
            let timer = std::time::SystemTime::now();
            let mut base_context =
                init_request_context(&req, enclave_context, feature_context.clone());
            // add context id as request header
            let request_id = base_context.get_trx_id();
            add_ev_ctx_to_headers(req.headers_mut(), &request_id);

            if let Some(RemoteIp(remote)) = req.extensions_mut().remove::<RemoteIp>() {
                base_context.remote_ip(Some(remote));
            }

            let _ = req.extensions_mut().insert(base_context);
            let mut response = inner.call(req).await?;
            let mut context = response
                .extensions_mut()
                .remove::<TrxContextBuilder>()
                .expect("Context not preserved on data plane response");
            context.add_res_to_trx_context(&response, &feature_context.trusted_headers);
            add_ev_ctx_to_headers(response.headers_mut(), &request_id);
            let Ok(built_context) = context.stop_timer_and_build(timer) else {
                log::error!("Failed to build trx context for request");
                return Ok(response);
            };

            if feature_context.trx_logging_enabled {
                //Send trx to config server in data plane
                if let Err(e) =
                    log_tx_sender.send(LogHandlerMessage::new_log_message(built_context))
                {
                    log::error!("Failed to send transaction context to log handler. err: {e}")
                }
            }

            Ok(response)
        })
    }
}

pub fn init_request_context<
    C: std::ops::Deref<Target = EnclaveContext>,
    F: std::ops::Deref<Target = FeatureContext>,
>(
    req: &Request<Body>,
    enclave_context: C,
    feature_context: F,
) -> TrxContextBuilder {
    let mut trx_ctx = TrxContextBuilder::init_trx_context_with_enclave_details(
        &enclave_context.uuid,
        &enclave_context.name,
        &enclave_context.app_uuid,
        &enclave_context.team_uuid,
        RequestType::HTTP,
    );
    trx_ctx.add_req_to_trx_context(req, &feature_context.trusted_headers);
    trx_ctx
}

fn add_ev_ctx_to_headers(headers: &mut HeaderMap, trx_id: &str) {
    headers.insert(
        "x-evervault-cage-ctx",
        hyper::header::HeaderValue::from_str(trx_id).expect("Infallible: txids are valid headers"),
    );
}
