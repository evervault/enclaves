use hyper::{client::HttpConnector, header, Body, Client, Method, Request};
use shared::server::health::HealthCheckStatus;
use std::collections::VecDeque;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

use crate::{CageContext, CageContextError};

enum HealthcheckAgentState {
    Initializing,
    Ready,
}

impl std::default::Default for HealthcheckAgentState {
    fn default() -> Self {
        Self::Initializing
    }
}

pub struct HealthcheckStatusRequest {
    sender: OneshotSender<HealthCheckStatus>,
}

impl HealthcheckStatusRequest {
    pub fn new() -> (Self, OneshotReceiver<HealthCheckStatus>) {
        let (sender, receiver) = oneshot_channel();
        (Self { sender }, receiver)
    }
}

pub type UserProcessHealthcheckSender = UnboundedSender<HealthcheckStatusRequest>;

pub struct HealthcheckAgent {
    healthcheck_path: Option<String>,
    buffer: VecDeque<HealthCheckStatus>,
    interval: std::time::Duration,
    state: HealthcheckAgentState,
    recv: UnboundedReceiver<HealthcheckStatusRequest>,
}

impl HealthcheckAgent {
    pub fn new(interval: std::time::Duration) -> (Self, UnboundedSender<HealthcheckStatusRequest>) {
        let (sender, recv) = unbounded_channel();
        let healthcheck_agent = Self {
            healthcheck_path: None,
            buffer: VecDeque::with_capacity(10),
            state: HealthcheckAgentState::default(),
            interval,
            recv,
        };
        (healthcheck_agent, sender)
    }

    #[cfg(feature = "tls_termination")]
    fn build_client() -> hyper::Client<HttpConnector, Body> {
        Client::builder().build_http()
    }

    #[cfg(not(feature = "tls_termination"))]
    fn build_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        use crate::base_tls_client::{
            tls_client_config::get_tls_client_config, OpenServerCertVerifier,
        };
        use hyper_rustls::HttpsConnectorBuilder;
        let tls_client_config = get_tls_client_config(OpenServerCertVerifier);
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_client_config)
            .https_only()
            .enable_all_versions()
            .build();
        Client::builder().build(https_connector)
    }

    fn check_user_process_initialized(&mut self) -> Result<HealthCheckStatus, CageContextError> {
        let contents = match std::fs::read_to_string("/etc/customer-env") {
            Ok(contents) => contents,
            Err(_) => return Ok(HealthCheckStatus::Err),
        };
        if contents.contains("EV_CAGE_INITIALIZED") {
            let ctx = CageContext::get()?;
            self.healthcheck_path = ctx.healthcheck.clone();
            self.state = HealthcheckAgentState::Ready;
            Ok(HealthCheckStatus::Ok)
        } else {
            Ok(HealthCheckStatus::Uninitialized)
        }
    }

    async fn perform_healthcheck(&mut self, client: &Client<HttpConnector, Body>) {
        let healthcheck_result = match self.state {
            HealthcheckAgentState::Initializing => {
                self.check_user_process_initialized().unwrap_or_else(|err| {
                    log::warn!("Error reading init state from user process env - {err:?}");
                    HealthCheckStatus::Err
                })
            }
            HealthcheckAgentState::Ready if self.healthcheck_path.is_some() => {
                Self::probe_user_process(client, self.healthcheck_path.as_deref().unwrap()).await
            }
            HealthcheckAgentState::Ready => HealthCheckStatus::Ok,
        };

        self.buffer.push_back(healthcheck_result);
    }

    async fn serve_healthcheck_request(&mut self, request: HealthcheckStatusRequest) {
        if self.buffer.is_empty() {
            let _ = request.sender.send(HealthCheckStatus::Uninitialized);
            return;
        }

        // Safety: Iterator checked to be non-empty at start of func
        let max_result = self.buffer.iter().max().unwrap();
        let _ = request.sender.send(max_result.to_owned());
    }

    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.interval);
        let client = Self::build_client();
        loop {
            tokio::select! {
              healthcheck_req = self.recv.recv() => {
                if let Some(req) = healthcheck_req {
                  self.serve_healthcheck_request(req).await;
                }
              },
              _ = interval.tick() => self.perform_healthcheck(&client).await
            }
        }
    }

    #[cfg(not(feature = "tls_termination"))]
    fn build_healthcheck_uri(healthcheck_path: &str) -> String {
        format!("https://127.0.0.1/{}", &healthcheck_path)
    }

    #[cfg(feature = "tls_termination")]
    fn build_healthcheck_uri(healthcheck_path: &str) -> String {
        format!("http://127.0.0.1/{}", &healthcheck_path)
    }

    async fn probe_user_process(
        client: &Client<HttpConnector, Body>,
        healthcheck_path: &str,
    ) -> HealthCheckStatus {
        let healthcheck_uri = Self::build_healthcheck_uri(&healthcheck_path);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&healthcheck_uri)
            .header(header::USER_AGENT, "Evervault-Healthcheck-Agent")
            .body(Body::empty())
            .expect("Failed to create user process healthcheck request");
        log::debug!("Probing user process from healthcheck agent - {healthcheck_uri}");
        match client.request(req).await {
            Ok(res) if res.status().is_success() => HealthCheckStatus::Ok,
            Ok(res) => {
                log::warn!(
                    "Status code {} returned from user process healthcheck",
                    res.status()
                );
                HealthCheckStatus::Err
            }
            Err(e) => {
                log::error!("Error sending healthcheck to user process - {e:?}");
                HealthCheckStatus::Err
            }
        }
    }
}
