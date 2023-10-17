use super::initialized::{EnclaveEnvInitialized, InitializedHealthcheck};
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

pub struct HealthcheckAgent<T: InitializedHealthcheck> {
    customer_process_port: u16,
    healthcheck_path: Option<String>,
    buffer: VecDeque<HealthCheckStatus>,
    interval: std::time::Duration,
    state: HealthcheckAgentState,
    recv: UnboundedReceiver<HealthcheckStatusRequest>,
    initialized_check: T,
    buffer_size_limit: usize
}

pub fn default_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
) -> (
    HealthcheckAgent<EnclaveEnvInitialized>,
    UnboundedSender<HealthcheckStatusRequest>,
) {
    HealthcheckAgent::new(
        customer_process_port,
        std::time::Duration::from_secs(1),
        healthcheck,
        EnclaveEnvInitialized,
    )
}

const DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT: usize = 10;

impl<T: InitializedHealthcheck> HealthcheckAgent<T> {
    pub fn new(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
        init_health_checker: T,
    ) -> (Self, UnboundedSender<HealthcheckStatusRequest>) {
        let (sender, recv) = unbounded_channel();
        let healthcheck_agent = Self {
            customer_process_port,
            healthcheck_path,
            buffer: VecDeque::with_capacity(DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT),
            state: HealthcheckAgentState::default(),
            interval,
            recv,
            initialized_check: init_health_checker,
            buffer_size_limit: DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT
        };
        (healthcheck_agent, sender)
    }

    fn record_result(&mut self, healthcheck_status: HealthCheckStatus) {
      self.buffer.push_back(healthcheck_status);
      if self.buffer.len() >= self.buffer_size_limit {
        self.buffer.pop_front();
      }
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
        let cert_verifier = std::sync::Arc::new(OpenServerCertVerifier);
        let tls_client_config = get_tls_client_config(cert_verifier);
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_client_config)
            .https_only()
            .enable_all_versions()
            .build();
        Client::builder().build(https_connector)
    }

    fn check_user_process_initialized(&mut self) -> Result<HealthCheckStatus, CageContextError> {
        let is_initialized = match self.initialized_check.is_initialized() {
            Ok(is_initialized) => is_initialized,
            Err(_) => return Ok(HealthCheckStatus::Err),
        };
        if is_initialized {
            let _ = CageContext::get()?;
            self.state = HealthcheckAgentState::Ready;
            Ok(HealthCheckStatus::Ok)
        } else {
            Ok(HealthCheckStatus::Uninitialized)
        }
    }

    async fn perform_healthcheck<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        &mut self,
        client: Client<C, Body>,
    ) {
        let healthcheck_result = match self.state {
            HealthcheckAgentState::Initializing => {
                self.check_user_process_initialized().unwrap_or_else(|err| {
                    log::warn!("Error reading init state from user process env - {err:?}");
                    HealthCheckStatus::Err
                })
            }
            HealthcheckAgentState::Ready if self.healthcheck_path.is_some() => {
                self.probe_user_process(client, self.healthcheck_path.as_deref().unwrap())
                    .await
            }
            HealthcheckAgentState::Ready => HealthCheckStatus::Ok,
        };

        self.record_result(healthcheck_result);
    }

    fn serve_healthcheck_request(&mut self, request: HealthcheckStatusRequest) {
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
                  self.serve_healthcheck_request(req);
                }
              },
              _ = interval.tick() => self.perform_healthcheck(client.clone()).await
            }
        }
    }

    #[cfg(not(feature = "tls_termination"))]
    fn build_healthcheck_uri(&self, healthcheck_path: &str) -> String {
        format!(
            "https://127.0.0.1:{}{}",
            self.customer_process_port, &healthcheck_path
        )
    }

    #[cfg(feature = "tls_termination")]
    fn build_healthcheck_uri(&self, healthcheck_path: &str) -> String {
        format!(
            "http://127.0.0.1:{}{}",
            self.customer_process_port, &healthcheck_path
        )
    }

    async fn probe_user_process<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        &self,
        client: Client<C, Body>,
        healthcheck_path: &str,
    ) -> HealthCheckStatus {
        let healthcheck_uri = self.build_healthcheck_uri(healthcheck_path);
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

#[cfg(test)]
mod test {
    use super::{default_agent, HealthCheckStatus, HealthcheckAgent, HealthcheckStatusRequest};
    use yup_hyper_mock::mock_connector;

    #[test]
    fn validate_ok_returned_from_healthy_buffer() {
        let (mut agent, _sender) = default_agent(3000, None);
        for _ in 0..5 {
            agent.buffer.push_back(HealthCheckStatus::Ok);
        }
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert_eq!(HealthCheckStatus::Ok, result);
    }

    #[test]
    fn validate_unitialized_returned_from_otherwise_healthy_buffer() {
        let (mut agent, _sender) = default_agent(3000, None);
        for _ in 0..5 {
            agent.buffer.push_back(HealthCheckStatus::Ok);
        }
        agent.buffer.push_back(HealthCheckStatus::Uninitialized);
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert_eq!(HealthCheckStatus::Uninitialized, result);
    }

    pub struct TestInitialized(bool);

    impl super::InitializedHealthcheck for TestInitialized {
        type Error = std::convert::Infallible;

        fn is_initialized(&self) -> Result<bool, Self::Error> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn validate_uninitialized_user_process_doesnt_return_errors() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3000, duration, None, TestInitialized(false));

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            HealthCheckStatus::Uninitialized
        );
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_no_healthcheck_path_returns_ok() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3000, duration, None, TestInitialized(false));
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(healthcheck_result.to_owned(), HealthCheckStatus::Ok);
    }

    #[cfg(feature = "tls_termination")]
    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_healthy() {
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            duration,
            Some("/healthz".into()),
            TestInitialized(false),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(healthcheck_result.to_owned(), HealthCheckStatus::Ok);
    }

    #[cfg(not(feature = "tls_termination"))]
    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_healthy() {
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            duration,
            Some("/healthz".into()),
            TestInitialized(false),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(healthcheck_result.to_owned(), HealthCheckStatus::Ok);
    }

    #[cfg(feature = "tls_termination")]
    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_error() {
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(
            3001,
            duration,
            Some("/healthcheck".into()),
            TestInitialized(false),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(healthcheck_result.to_owned(), HealthCheckStatus::Err);
    }

    #[cfg(not(feature = "tls_termination"))]
    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_error() {
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(
            3001,
            duration,
            Some("/healthcheck".into()),
            TestInitialized(false),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(healthcheck_result.to_owned(), HealthCheckStatus::Err);
    }
}
