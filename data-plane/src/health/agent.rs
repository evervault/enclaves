use hyper::client::connect::Connect;
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

pub struct HealthcheckAgent<C> {
    customer_process_port: u16,
    healthcheck_path: Option<String>,
    client: hyper::Client<C, Body>,
    buffer: VecDeque<UserProcessHealth>,
    interval: std::time::Duration,
    state: HealthcheckAgentState,
    recv: UnboundedReceiver<HealthcheckStatusRequest>,
    buffer_size_limit: usize,
    proto: String,
}

const DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT: usize = 10;

#[derive(Error, Debug)]
enum UserProcessHealthCheckError {
    #[error("There was an error checking the initialization state of the user process - {0}")]
    InitializationCheck(#[from] ContextError),
    #[error("There was an error sending the healthcheck request to the user process - {0}")]
    HealthcheckRequest(#[from] hyper::Error),
}

impl HealthcheckAgent<hyper_rustls::HttpsConnector<HttpConnector>> {
    pub fn build_tls_agent(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
    ) -> (Self, UnboundedSender<HealthcheckStatusRequest>) {
        let client = Self::build_tls_client();
        Self::new(
            customer_process_port,
            interval,
            healthcheck_path,
            client,
            "https".into(),
        )
    }

    fn build_tls_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
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
}

impl HealthcheckAgent<HttpConnector> {
    pub fn build_agent(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
    ) -> (Self, UnboundedSender<HealthcheckStatusRequest>) {
        let client = Client::builder().build_http();
        Self::new(
            customer_process_port,
            interval,
            healthcheck_path,
            client,
            "http".into(),
        )
    }
}

impl<C: Connect + Clone + Send + Sync + 'static> HealthcheckAgent<C> {
    fn new(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
        client: hyper::Client<C>,
        proto: String,
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
            client,
            proto,
        };
        (healthcheck_agent, sender)
    }

    fn record_result(&mut self, healthcheck_status: UserProcessHealth) {
        self.buffer.push_back(healthcheck_status);
        if self.buffer.len() >= self.buffer_size_limit {
            self.buffer.pop_front();
        }
    }

    fn check_user_process_initialized(&mut self) -> Result<HealthcheckAgentState, ContextError> {
        let new_state = match std::fs::read_to_string("/etc/customer-env") {
            Ok(c) => {
                if c.contains("EV_INITIALIZED") {
                    let _ = EnclaveContext::get()?;
                    self.state = HealthcheckAgentState::Ready;
                    HealthcheckAgentState::Ready
                } else {
                    HealthcheckAgentState::Initializing
                }
            }

            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => HealthcheckAgentState::Initializing,
                _ => return Err(e.into()),
            },
        };

        Ok(new_state)
    }

    async fn perform_healthcheck(&mut self) {
        let hc_state = match self.state {
            HealthcheckAgentState::Initializing => self.check_user_process_initialized(),
            _ => Ok(HealthcheckAgentState::Ready),
        };

        let hc_result = match hc_state {
            Ok(HealthcheckAgentState::Ready) if self.healthcheck_path.is_some() => {
                self.probe_user_process(self.healthcheck_path.as_deref().unwrap())
                    .await
            }
            Ok(HealthcheckAgentState::Ready) => {
                UserProcessHealth::Unknown("No healthcheck path provided".to_string())
            }
            Ok(HealthcheckAgentState::Initializing) => {
                UserProcessHealth::Unknown("Enclave is not initialized yet".to_string())
            }
            Err(e) => UserProcessHealth::Error(format!(
                "Error reading init state from user process env - {e:?}"
            )),
        };

        self.record_result(hc_result);
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
        log::info!("Starting healthcheck agent");
        let mut interval = tokio::time::interval(self.interval);
        loop {
            tokio::select! {
              healthcheck_req = self.recv.recv() => {
                if let Some(req) = healthcheck_req {
                  self.serve_healthcheck_request(req);
                }
              },
              _ = interval.tick() => self.perform_healthcheck().await
            }
        }
    }

    fn build_healthcheck_uri(&self, healthcheck_path: &str) -> String {
        format!(
            "{}://127.0.0.1:{}{}",
            &self.proto, self.customer_process_port, &healthcheck_path
        )
    }

    async fn probe_user_process(&self, healthcheck_path: &str) -> UserProcessHealth {
        let healthcheck_uri = self.build_healthcheck_uri(healthcheck_path);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&healthcheck_uri)
            .header(header::USER_AGENT, "Evervault-Healthcheck-Agent")
            .body(Body::empty())
            .expect("Failed to create user process healthcheck request");
        log::debug!("Probing user process from healthcheck agent - {healthcheck_uri}");
        match self.client.request(req).await {
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
                    .map(|b| serde_json::from_slice::<Value>(&b).ok())
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
    use super::{HealthcheckAgent, HealthcheckStatusRequest};
    use shared::server::health::UserProcessHealth;
    use test_case::case;
    use yup_hyper_mock::mock_connector;

    mock_connector!(MockHttpHealthyEmptyEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
    });

    mock_connector!(MockHttpsHealthyEmptyEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
    });

    mock_connector!(MockHttpUnhealthyEmptyEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
    });

    mock_connector!(MockHttpsUnhealthyEmptyEndpoint {
      "https://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
    });

    mock_connector!(MockHttpsHealthyJsonEndpoint {
      "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n{\"status\": \"ok\"}"
    });

    mock_connector!(MockHttpHealthyJsonEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n{\"status\": \"ok\"}"
    });

    mock_connector!(MockHttpUnhealthyJsonEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"very-bad-state\": \"unhealthy\"}"
    });

    mock_connector!(MockHttpsUnhealthyJsonEndpoint {
      "https://127.0.0.1" => "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"very-bad-state\": \"unhealthy\"}"
    });

    #[test]
    fn validate_response_returned_from_healthy_buffer() {
        let (mut agent, _sender) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);
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
        let (mut agent, _sender) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);
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
        let (mut agent, _sender) = HealthcheckAgent::build_agent(3000, duration, None);

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_no_healthcheck_path_returns_unknown() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::build_agent(3000, duration, None);
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ))
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_response() {
        let client = hyper::Client::builder().build(MockHttpHealthyEmptyEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            None,
            client,
            "http".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            }
        );
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_response_over_tls() {
        let client = hyper::Client::builder().build(MockHttpsHealthyEmptyEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthz".into()),
            client,
            "https".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: None
            }
        );
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_response_with_correct_status(
    ) {
        let client = hyper::Client::builder().build(MockHttpUnhealthyEmptyEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "http".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 400,
                body: None
            }
        );
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_unhealthy_response_returns_response_with_correct_status_over_tls(
    ) {
        let client = hyper::Client::builder().build(MockHttpsUnhealthyEmptyEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3001,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "https".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 400,
                body: None
            }
        );
    }

    #[tokio::test]
    async fn it_can_parse_json_responses_from_user_process() {
        let client = hyper::Client::builder().build(MockHttpHealthyJsonEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "http".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: Some(serde_json::json!({"status": "ok"}))
            }
        );
    }

    #[tokio::test]
    async fn it_can_parse_json_responses_from_user_process_over_tls() {
        let client = hyper::Client::builder().build(MockHttpsHealthyJsonEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "https".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 200,
                body: Some(serde_json::json!({"status": "ok"}))
            }
        );
    }

    #[tokio::test]
    async fn it_can_parse_unhealthy_json_responses_from_user_process() {
        let client = hyper::Client::builder().build(MockHttpUnhealthyJsonEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "http".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 500,
                body: Some(serde_json::json!({"very-bad-state": "unhealthy"}))
            }
        );
    }

    #[tokio::test]
    async fn it_can_parse_unhealthy_json_responses_from_user_process_over_tls() {
        let client = hyper::Client::builder().build(MockHttpsUnhealthyJsonEndpoint::default());
        let (mut agent, _sender) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "https".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 500,
                body: Some(serde_json::json!({"very-bad-state": "unhealthy"}))
            }
        );
    }
}
