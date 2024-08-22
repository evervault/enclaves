use hyper::{client::HttpConnector, header, Body, Client, Method, Request};
use serde_json::Value;
use shared::server::health::UserProcessHealth;
use std::collections::VecDeque;
use thiserror::Error;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

use crate::{ContextError, EnclaveContext};

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
    sender: OneshotSender<UserProcessHealth>,
}

impl HealthcheckStatusRequest {
    pub fn new() -> (Self, OneshotReceiver<UserProcessHealth>) {
        let (sender, receiver) = oneshot_channel();
        (Self { sender }, receiver)
    }
}

pub type UserProcessHealthcheckSender = UnboundedSender<HealthcheckStatusRequest>;

pub struct HealthcheckAgent {
    customer_process_port: u16,
    healthcheck_path: Option<String>,
    buffer: VecDeque<UserProcessHealth>,
    interval: std::time::Duration,
    state: HealthcheckAgentState,
    recv: UnboundedReceiver<HealthcheckStatusRequest>,
    buffer_size_limit: usize,
}

pub fn default_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
) -> (HealthcheckAgent, UnboundedSender<HealthcheckStatusRequest>) {
    HealthcheckAgent::new(
        customer_process_port,
        std::time::Duration::from_secs(1),
        healthcheck,
    )
}

const DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT: usize = 10;

#[derive(Error, Debug)]
enum UserProcessHealthCheckError {
    #[error("There was an error checking the initialization state of the user process - {0}")]
    InitializationCheck(#[from] ContextError),
    #[error("There was an error sending the healthcheck request to the user process - {0}")]
    HealthcheckRequest(#[from] hyper::Error),
}

impl HealthcheckAgent {
    pub fn new(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
    ) -> (Self, UnboundedSender<HealthcheckStatusRequest>) {
        let (sender, recv) = unbounded_channel();
        let healthcheck_agent = Self {
            customer_process_port,
            healthcheck_path,
            buffer: VecDeque::with_capacity(DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT),
            state: HealthcheckAgentState::default(),
            interval,
            recv,
            buffer_size_limit: DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT,
        };
        (healthcheck_agent, sender)
    }

    fn record_result(&mut self, healthcheck_status: UserProcessHealth) {
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

    fn check_user_process_initialized(&mut self) -> Result<bool, ContextError> {
        let is_initialized = match std::fs::read_to_string("/etc/customer-env") {
            Ok(c) => Ok(c.contains("EV_INITIALIZED")),
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => Ok(false),
                _ => Err(e),
            },
        }?;

        if is_initialized {
            let _ = EnclaveContext::get()?;
            self.state = HealthcheckAgentState::Ready;
        }

        Ok(is_initialized)
    }

    async fn perform_healthcheck<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        &mut self,
        client: Client<C, Body>,
    ) {
        let healthcheck_result = match self.state {
            HealthcheckAgentState::Initializing => match self.check_user_process_initialized() {
                Ok(_) => UserProcessHealth::Unknown("Enclave is not initialized yet".to_string()),
                Err(err) => {
                    log::warn!("Error reading init state from user process env - {err:?}");

                    UserProcessHealth::Error(format!(
                        "Error reading init state from user process env - {err:?}"
                    ))
                }
            },
            HealthcheckAgentState::Ready if self.healthcheck_path.is_some() => {
                self.probe_user_process(client, self.healthcheck_path.as_deref().unwrap())
                    .await
            }
            HealthcheckAgentState::Ready => {
                UserProcessHealth::Unknown("No healthcheck path provided".to_string())
            }
        };

        self.record_result(healthcheck_result);
    }

    fn serve_healthcheck_request(&mut self, request: HealthcheckStatusRequest) {
        if self.buffer.is_empty() {
            let _ = request.sender.send(UserProcessHealth::Unknown(
                "Enclave is not initialized yet".to_string(),
            ));
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
    ) -> UserProcessHealth {
        let healthcheck_uri = self.build_healthcheck_uri(healthcheck_path);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&healthcheck_uri)
            .header(header::USER_AGENT, "Evervault-Healthcheck-Agent")
            .body(Body::empty())
            .expect("Failed to create user process healthcheck request");
        log::debug!("Probing user process from healthcheck agent - {healthcheck_uri}");
        match client.request(req).await {
            Ok(res) => {
                let (parts, body) = res.into_parts();
                if !parts.status.is_success() {
                    log::warn!(
                        "Status code {} returned from user process healthcheck",
                        parts.status
                    );
                }

                let json = hyper::body::to_bytes(body)
                    .await
                    .map(move |b| serde_json::from_slice::<Value>(&b).ok())
                    .ok()
                    .flatten();

                UserProcessHealth::Response {
                    status_code: parts.status.as_u16(),
                    body: json,
                }
            }
            Err(e) => {
                log::error!("Error sending healthcheck to user process - {e:?}");
                UserProcessHealth::Error(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{default_agent, HealthcheckAgent, HealthcheckStatusRequest};
    use shared::server::health::UserProcessHealth;
    use yup_hyper_mock::mock_connector;

    #[test]
    fn validate_response_returned_from_healthy_buffer() {
        let (mut agent, _sender) = default_agent(3000, None);
        for _ in 0..5 {
            agent.buffer.push_back(UserProcessHealth::Response {
                status_code: 200,
                body: None,
            });
        }
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(
            result,
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            },
        ));
    }

    #[test]
    fn validate_response_returned_from_buffer_with_unknown() {
        let (mut agent, _sender) = default_agent(3000, None);
        for _ in 0..5 {
            agent.buffer.push_back(UserProcessHealth::Response {
                status_code: 200,
                body: None,
            });
        }
        agent.buffer.push_back(UserProcessHealth::Unknown(
            "Enclave is not initialized yet".to_string(),
        ));
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(
            result,
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            }
        ));
    }

    #[tokio::test]
    async fn validate_uninitialized_user_process_doesnt_return_errors() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, None);

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_no_healthcheck_path_returns_unknown() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, None);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ))
    }

    #[cfg(feature = "tls_termination")]
    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_response() {
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, Some("/healthz".into()));
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            }
        );
    }

    #[cfg(not(feature = "tls_termination"))]
    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_response() {
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, Some("/healthz".into()));
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            }
        );
    }

    #[cfg(feature = "tls_termination")]
    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_response_with_correct_status(
    ) {
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()));
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 400,
                body: None
            }
        );
    }

    #[cfg(not(feature = "tls_termination"))]
    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_response_with_correct_status(
    ) {
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()));
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 400,
                body: None
            }
        );
    }
}
