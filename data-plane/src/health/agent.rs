use hyper::{client::HttpConnector, header, Body, Client, Method, Request};
use serde_json::Value;
use shared::server::diagnostic::Diagnostic;
use shared::server::health::{DataPlaneDiagnostic, UserProcessHealth};
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

pub struct HealthcheckAgentRequest {
    sender: OneshotSender<DataPlaneDiagnostic>,
}

impl HealthcheckAgentRequest {
    pub fn new() -> (Self, OneshotReceiver<DataPlaneDiagnostic>) {
        let (sender, receiver) = oneshot_channel();
        (Self { sender }, receiver)
    }
}

pub type HealthcheckAgentSender = UnboundedSender<HealthcheckAgentRequest>;
pub type DiagnosticReceiver = UnboundedReceiver<Diagnostic>;

pub struct HealthcheckAgent {
    customer_process_port: u16,
    healthcheck_path: Option<String>,
    hc_buffer: VecDeque<UserProcessHealth>,
    diag_buffer: VecDeque<Diagnostic>,
    interval: std::time::Duration,
    state: HealthcheckAgentState,
    recv: UnboundedReceiver<HealthcheckAgentRequest>,
    diag_recv: DiagnosticReceiver,
    buffer_size_limit: usize,
}

pub fn default_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
    diag_recv: DiagnosticReceiver,
) -> (HealthcheckAgent, UnboundedSender<HealthcheckAgentRequest>) {
    HealthcheckAgent::new(
        customer_process_port,
        std::time::Duration::from_secs(1),
        healthcheck,
        diag_recv,
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
        diag_recv: DiagnosticReceiver,
    ) -> (Self, UnboundedSender<HealthcheckAgentRequest>) {
        let (sender, recv) = unbounded_channel();
        let healthcheck_agent = Self {
            customer_process_port,
            healthcheck_path,
            hc_buffer: VecDeque::with_capacity(DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT),
            diag_buffer: VecDeque::with_capacity(DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT),
            state: HealthcheckAgentState::default(),
            interval,
            recv,
            diag_recv,
            buffer_size_limit: DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT,
        };
        (healthcheck_agent, sender)
    }

    fn record_diag(&mut self, diag: Diagnostic) {
        self.diag_buffer.push_back(diag);
        if self.diag_buffer.len() >= self.buffer_size_limit {
            self.diag_buffer.pop_front();
        }
    }

    fn record_result(&mut self, healthcheck_status: UserProcessHealth) {
        self.hc_buffer.push_back(healthcheck_status);
        if self.hc_buffer.len() >= self.buffer_size_limit {
            self.hc_buffer.pop_front();
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

    async fn perform_healthcheck<
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    >(
        &mut self,
        client: Client<C, Body>,
    ) {
        let hc_state = match self.state {
            HealthcheckAgentState::Initializing => self.check_user_process_initialized(),
            _ => Ok(HealthcheckAgentState::Ready),
        };

        let hc_result = match hc_state {
            Ok(HealthcheckAgentState::Ready) if self.healthcheck_path.is_some() => {
                self.probe_user_process(client, self.healthcheck_path.as_deref().unwrap())
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

    fn serve_healthcheck_request(&mut self, request: HealthcheckAgentRequest) {
        let user_process = if self.hc_buffer.is_empty() {
            UserProcessHealth::Unknown("Enclave is not initialized yet".to_string())
        } else {
            self.hc_buffer.iter().max().unwrap().to_owned()
        };

        if request
            .sender
            .send(DataPlaneDiagnostic {
                user_process,
                diagnostics: self.diag_buffer.clone().into(),
            })
            .is_ok()
        {
            self.diag_buffer.clear();
        };
    }

    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.interval);
        let client = Self::build_client();
        loop {
            tokio::select! {
              Some(hc_req) = self.recv.recv() => {
                  self.serve_healthcheck_request(hc_req);
              },
              Some(diag) = self.diag_recv.recv() => {
                self.record_diag(diag);
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
    use super::{
        default_agent, HealthcheckAgent, HealthcheckAgentRequest,
        DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT,
    };
    use serde_json::json;
    use shared::server::{
        diagnostic::Diagnostic,
        health::{DataPlaneDiagnostic, UserProcessHealth},
    };
    use tokio::sync::mpsc;
    use yup_hyper_mock::mock_connector;

    #[test]
    fn validate_response_returned_from_healthy_buffer() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let (mut agent, _sender) = default_agent(3000, None, diag_recv);
        for _ in 0..5 {
            agent.hc_buffer.push_back(UserProcessHealth::Response {
                status_code: 200,
                body: None,
            });
        }
        let (req, mut receiver) = HealthcheckAgentRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(
            result,
            DataPlaneDiagnostic {
                user_process: UserProcessHealth::Response {
                    status_code: 200,
                    body: None
                },
                ..
            },
        ));
    }

    #[test]
    fn validate_response_returned_from_buffer_with_unknown() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let (mut agent, _sender) = default_agent(3000, None, diag_recv);
        for _ in 0..5 {
            agent.hc_buffer.push_back(UserProcessHealth::Response {
                status_code: 200,
                body: None,
            });
        }
        agent.hc_buffer.push_back(UserProcessHealth::Unknown(
            "Enclave is not initialized yet".to_string(),
        ));
        let (req, mut receiver) = HealthcheckAgentRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(
            result,
            DataPlaneDiagnostic {
                user_process: UserProcessHealth::Response {
                    status_code: 200,
                    body: None,
                },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn validate_uninitialized_user_process_doesnt_return_errors() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();

        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, None, diag_recv);

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ));
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_no_healthcheck_path_returns_unknown() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();

        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) = HealthcheckAgent::new(3000, duration, None, diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build_http();
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
        assert!(matches!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Unknown(_)
        ))
    }

    #[tokio::test]
    async fn validate_initialized_agent_with_healthy_response_returns_response() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        #[cfg(feature = "tls_termination")]
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });
        #[cfg(not(feature = "tls_termination"))]
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
        });

        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3000, duration, Some("/healthz".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
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
        #[cfg(feature = "tls_termination")]
        mock_connector!(MockHealthcheckEndpoint {
          "http://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });
        #[cfg(not(feature = "tls_termination"))]
        mock_connector!(MockHealthcheckEndpoint {
          "https://127.0.0.1" => "HTTP/1.1 400 Bad Request\r\n\r\n"
        });

        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
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
        #[cfg(feature = "tls_termination")]
        mock_connector!(MockHealthcheckEndpoint {
              "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n{\"status\": \"ok\"}"
        });
        #[cfg(not(feature = "tls_termination"))]
        mock_connector!(MockHealthcheckEndpoint {
              "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n{\"status\": \"ok\"}"
        });

        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();

        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
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
        #[cfg(feature = "tls_termination")]
        mock_connector!(MockHealthcheckEndpoint {
            "http://127.0.0.1" => "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"very-bad-state\": \"unhealthy\"}"
        });
        #[cfg(not(feature = "tls_termination"))]
        mock_connector!(MockHealthcheckEndpoint {
            "https://127.0.0.1" => "HTTP/1.1 500 Internal Server Error\r\n\r\n{\"very-bad-state\": \"unhealthy\"}"
        });

        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        let client = hyper::Client::builder().build(MockHealthcheckEndpoint::default());
        agent.perform_healthcheck(client).await;

        let healthcheck_result = agent.hc_buffer.iter().max().unwrap();
        assert_eq!(
            healthcheck_result.to_owned(),
            UserProcessHealth::Response {
                status_code: 500,
                body: Some(serde_json::json!({"very-bad-state": "unhealthy"}))
            }
        );
    }

    #[tokio::test]
    async fn it_returns_stored_diagnostics() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        agent.diag_buffer.push_back(Diagnostic {
            label: "MockService".to_string(),
            data: json!({ "feeling": "good" }),
        });

        let (req, mut receiver) = HealthcheckAgentRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();

        assert_eq!(
            result.diagnostics.get(0).unwrap().label,
            "MockService".to_string()
        );
        assert_eq!(
            result.diagnostics.get(0).unwrap().data,
            json!({ "feeling": "good" })
        );
        assert_eq!(result.diagnostics.len(), 1);
    }

    #[tokio::test]
    async fn it_empties_the_diag_buffer_after_responding_to_hc() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        agent.diag_buffer.push_back(Diagnostic {
            label: "MockService".to_string(),
            data: json!({ "feeling": "good" }),
        });

        let (req, mut rx) = HealthcheckAgentRequest::new();
        let _ = rx.try_recv();

        agent.serve_healthcheck_request(req);

        assert_eq!(agent.diag_buffer.len(), 0);
    }

    #[tokio::test]
    async fn it_limits_the_diag_buffers_size() {
        let (_, diag_recv) = mpsc::unbounded_channel::<Diagnostic>();
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender) =
            HealthcheckAgent::new(3001, duration, Some("/healthcheck".into()), diag_recv);
        agent.state = super::HealthcheckAgentState::Ready;

        for _ in 0..DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT + 5 {
            agent.record_diag(Diagnostic {
                label: "MockService".to_string(),
                data: json!({ "feeling": "good" }),
            });
        }

        let (req, _) = HealthcheckAgentRequest::new();
        agent.serve_healthcheck_request(req);

        assert_eq!(
            agent.diag_buffer.len(),
            DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT - 1
        );
    }
}
