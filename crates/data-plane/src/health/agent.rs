use crate::{ContextError, EnclaveContext};
use hyper::client::connect::Connect;
use hyper::{client::HttpConnector, header, Body, Client, Method, Request};
use serde_json::Value;
use shared::{
    notify_shutdown::Service,
    server::health::{DataPlaneDiagnostic, DataPlaneState, UserProcessHealth},
};
use std::collections::VecDeque;
use std::marker::PhantomData;
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};
use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

#[derive(Default)]
enum HealthcheckAgentState {
    #[default]
    Initializing,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BootPhase {
    #[default]
    Provisioning,
    Attesting,
    #[cfg(feature = "tls_termination")]
    SourcingTlsCerts,
}

impl std::fmt::Display for BootPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let phase = match self {
            BootPhase::Provisioning => "Provisioning",
            BootPhase::Attesting => "Attesting",
            #[cfg(feature = "tls_termination")]
            BootPhase::SourcingTlsCerts => "Sourcing TLS certificates",
        };
        write!(f, "{phase}")
    }
}

pub trait BootPhaseMarker {}

/// The data plane has started but not yet begun fetching its environment.
pub struct Provisioning;
impl BootPhaseMarker for Provisioning {}

/// The data plane is attesting to the provisioner to fetch and decrypt its environment.
pub struct Attesting;
impl BootPhaseMarker for Attesting {}

/// The data plane is sourcing its TLS certificates from the provisioner.
pub struct SourcingTlsCerts;
impl BootPhaseMarker for SourcingTlsCerts {}

pub struct BootProgress<P: BootPhaseMarker> {
    sender: UnboundedSender<BootPhase>,
    _phase: PhantomData<P>,
}

impl BootProgress<Provisioning> {
    fn new(sender: UnboundedSender<BootPhase>) -> Self {
        Self {
            sender,
            _phase: PhantomData,
        }
    }

    pub fn attesting(self) -> BootProgress<Attesting> {
        let _ = self.sender.send(BootPhase::Attesting);
        BootProgress {
            sender: self.sender,
            _phase: PhantomData,
        }
    }
}

#[cfg(feature = "tls_termination")]
impl BootProgress<Attesting> {
    pub fn sourcing_tls_certs(self) -> BootProgress<SourcingTlsCerts> {
        let _ = self.sender.send(BootPhase::SourcingTlsCerts);
        BootProgress {
            sender: self.sender,
            _phase: PhantomData,
        }
    }
}

pub struct HealthcheckStatusRequest {
    sender: OneshotSender<DataPlaneState>,
}

impl HealthcheckStatusRequest {
    pub fn new() -> (Self, OneshotReceiver<DataPlaneState>) {
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
    boot_phase: BootPhase,
    boot_phase_receiver: UnboundedReceiver<BootPhase>,
    awaiting_boot_phases: bool,
    recv: UnboundedReceiver<HealthcheckStatusRequest>,
    buffer_size_limit: usize,
    proto: String,
    shutdown_receiver: Receiver<Service>,
    exited_services: Vec<Service>,
}

const DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT: usize = 10;

impl HealthcheckAgent<hyper_rustls::HttpsConnector<HttpConnector>> {
    pub fn build_tls_agent(
        customer_process_port: u16,
        interval: std::time::Duration,
        healthcheck_path: Option<String>,
    ) -> (
        Self,
        UnboundedSender<HealthcheckStatusRequest>,
        Sender<Service>,
        BootProgress<Provisioning>,
    ) {
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
    ) -> (
        Self,
        UnboundedSender<HealthcheckStatusRequest>,
        Sender<Service>,
        BootProgress<Provisioning>,
    ) {
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
    ) -> (
        Self,
        UnboundedSender<HealthcheckStatusRequest>,
        Sender<Service>,
        BootProgress<Provisioning>,
    ) {
        let (sender, recv) = unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = channel(1);
        let (boot_phase_sender, boot_phase_receiver) = unbounded_channel();

        let critical_service_vec = if cfg!(feature = "network_egress") {
            Vec::with_capacity(5)
        } else {
            Vec::with_capacity(3)
        };

        let healthcheck_agent = Self {
            customer_process_port,
            healthcheck_path,
            buffer: VecDeque::with_capacity(DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT),
            state: HealthcheckAgentState::default(),
            boot_phase: BootPhase::default(),
            boot_phase_receiver,
            awaiting_boot_phases: true,
            interval,
            recv,
            buffer_size_limit: DEFAULT_HEALTHCHECK_BUFFER_SIZE_LIMIT,
            client,
            proto,
            shutdown_receiver,
            exited_services: critical_service_vec,
        };
        (
            healthcheck_agent,
            sender,
            shutdown_sender,
            BootProgress::new(boot_phase_sender),
        )
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

    fn serialize_exited_services(&self) -> String {
        self.exited_services
            .iter()
            .map(|service| service.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    async fn perform_healthcheck(&mut self) {
        let hc_state = match self.state {
            HealthcheckAgentState::Initializing => self.check_user_process_initialized(),
            _ => Ok(HealthcheckAgentState::Ready),
        };

        let hc_result = match hc_state {
            Ok(HealthcheckAgentState::Ready) => {
                if let Ok(exited_service) = self.shutdown_receiver.try_recv() {
                    self.exited_services.push(exited_service);
                    UserProcessHealth::Error(format!(
                        "Critical in-Enclave services have exited: {}",
                        self.serialize_exited_services()
                    ))
                } else if !self.exited_services.is_empty() {
                    UserProcessHealth::Error(format!(
                        "Critical in-Enclave services have exited: {}",
                        self.serialize_exited_services()
                    ))
                } else if self.healthcheck_path.is_some() {
                    self.probe_user_process(self.healthcheck_path.as_deref().unwrap())
                        .await
                } else {
                    UserProcessHealth::Unknown("No healthcheck path provided".to_string())
                }
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

    fn record_boot_phase(&mut self, boot_phase: BootPhase) {
        log::debug!(
            "{}",
            json!({"msg": "Data plane boot phase transitioned", "to": boot_phase})
        );
        self.boot_phase = boot_phase;
    }

    fn serve_healthcheck_request(&mut self, request: HealthcheckStatusRequest) {
        let state = match self.state {
            HealthcheckAgentState::Initializing => match self.boot_phase {
                BootPhase::Provisioning => DataPlaneState::Provisioning,
                BootPhase::Attesting => DataPlaneState::Attesting,
                #[cfg(feature = "tls_termination")]
                BootPhase::SourcingTlsCerts => DataPlaneState::SourcingTlsCerts,
            },
            HealthcheckAgentState::Ready => {
                let user_process = self.buffer.iter().max().cloned().unwrap_or_else(|| {
                    UserProcessHealth::Unknown("No healthcheck results recorded yet".to_string())
                });
                DataPlaneState::Initialized(DataPlaneDiagnostic { user_process })
            }
        };
        let _ = request.sender.send(state);
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
              maybe_boot_phase = self.boot_phase_receiver.recv(), if self.awaiting_boot_phases => {
                match maybe_boot_phase {
                  Some(boot_phase) => self.record_boot_phase(boot_phase),
                  None => self.awaiting_boot_phases = false,
                }
              },
              _ = interval.tick() => self.perform_healthcheck().await
            }
        }
    }

    fn build_healthcheck_uri(&self, healthcheck_path: &str) -> String {
        format!(
            "{}://127.0.0.1:{}{}",
            self.proto, self.customer_process_port, healthcheck_path
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
    use super::{BootPhase, HealthcheckAgent, HealthcheckAgentState, HealthcheckStatusRequest};
    use shared::server::health::{DataPlaneDiagnostic, DataPlaneState, UserProcessHealth};
    use yup_hyper_mock::mock_connector;

    mock_connector!(MockHttpHealthyEmptyEndpoint {
      "http://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
    });

    mock_connector!(MockHttpsHealthyEmptyEndpoint {
      "https://127.0.0.1" => "HTTP/1.1 200 Ok\r\n\r\n"
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
    fn validate_uninitialized_agent_reports_provisioning() {
        let (mut agent, _sender, _, _) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);
        agent.buffer.push_back(UserProcessHealth::Response {
            status_code: 200,
            body: None,
        });
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(result, DataPlaneState::Provisioning));
    }

    #[test]
    fn validate_agent_reports_attesting_while_initializing() {
        let (mut agent, _sender, _, _) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);

        agent.boot_phase = BootPhase::Attesting;
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);
        assert!(matches!(
            receiver.try_recv().unwrap(),
            DataPlaneState::Attesting
        ));
    }

    #[cfg(feature = "tls_termination")]
    #[test]
    fn validate_agent_reports_sourcing_tls_certs_while_initializing() {
        let (mut agent, _sender, _, _) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);

        agent.boot_phase = BootPhase::SourcingTlsCerts;
        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);
        assert!(matches!(
            receiver.try_recv().unwrap(),
            DataPlaneState::SourcingTlsCerts
        ));
    }

    #[test]
    fn validate_boot_phase_transitions_are_recorded_and_reported() {
        let (mut agent, _sender, _, boot_progress) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);

        assert_eq!(agent.boot_phase, BootPhase::default());

        let boot_progress = boot_progress.attesting();
        let phase = agent.boot_phase_receiver.try_recv().unwrap();
        agent.record_boot_phase(phase);
        assert_eq!(agent.boot_phase, BootPhase::Attesting);

        let (req, mut receiver) = HealthcheckStatusRequest::new();
        agent.serve_healthcheck_request(req);
        assert!(matches!(
            receiver.try_recv().unwrap(),
            DataPlaneState::Attesting
        ));

        drop(boot_progress);
    }

    #[test]
    fn validate_response_returned_from_healthy_buffer() {
        let (mut agent, _sender, _, _) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);
        agent.state = HealthcheckAgentState::Ready;
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
            DataPlaneState::Initialized(DataPlaneDiagnostic {
                user_process: UserProcessHealth::Response {
                    status_code: 200,
                    body: None
                },
                ..
            }),
        ));
    }

    #[test]
    fn validate_response_returned_from_buffer_with_unknown() {
        let (mut agent, _sender, _, _) =
            HealthcheckAgent::build_agent(3000, std::time::Duration::from_secs(1), None);
        agent.state = HealthcheckAgentState::Ready;
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
            DataPlaneState::Initialized(DataPlaneDiagnostic {
                user_process: UserProcessHealth::Response {
                    status_code: 200,
                    body: None
                },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn validate_uninitialized_user_process_doesnt_return_errors() {
        let duration = std::time::Duration::from_secs(1);
        let (mut agent, _sender, _, _) = HealthcheckAgent::build_agent(3000, duration, None);

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
        let (mut agent, _sender, _, _) = HealthcheckAgent::build_agent(3000, duration, None);
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthz".into()),
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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
        let (mut agent, _sender, _, _) = HealthcheckAgent::new(
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

    #[tokio::test]
    async fn it_fails_all_healthchecks_if_critical_service_has_exited() {
        let client = hyper::Client::builder().build(MockHttpHealthyEmptyEndpoint::default());
        let (mut agent, _sender, shutdown_channel, _) = HealthcheckAgent::new(
            3000,
            std::time::Duration::from_secs(1),
            Some("/healthcheck".into()),
            client,
            "https".into(),
        );
        agent.state = super::HealthcheckAgentState::Ready;
        shutdown_channel
            .try_send(shared::notify_shutdown::Service::DataPlane)
            .unwrap();

        agent.perform_healthcheck().await;

        let healthcheck_result = agent.buffer.iter().max().unwrap();
        assert!(healthcheck_result.is_error());
        // clear agent buffer to remove above error
        agent.buffer.clear();
        // perform additional healthcheck to assert the healthcheck fails again
        agent.perform_healthcheck().await;
        let next_result = agent.buffer.iter().max().unwrap();
        assert!(next_result.is_error());
    }
}
