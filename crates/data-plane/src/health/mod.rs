mod agent;

use agent::UserProcessHealthcheckSender;

use hyper::header;
use hyper::{service::service_fn, Body, Response};
use shared::bridge::{Bridge, BridgeInterface, BridgeServer, Direction};
use shared::notify_shutdown::Service;
use shared::server::health::{DataPlaneDiagnostic, DataPlaneState, UserProcessHealth};
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};
use tokio::sync::mpsc::Sender;

use crate::health::agent::{HealthcheckAgent, HealthcheckStatusRequest};

/// Handle to a running healthcheck agent. Pairs the channel used to read the user process' latest
/// health with the channel that critical in-Enclave services use to report an unexpected exit, so
/// that the agent can be driven and observed independently of the healthcheck server it backs.
#[derive(Clone)]
pub struct HealthcheckAgentHandle {
    user_process_healthcheck_channel: UserProcessHealthcheckSender,
    shutdown_notifier: Sender<Service>,
}

impl HealthcheckAgentHandle {
    /// Spawn a healthcheck agent to poll the user process, returning a handle to the running agent.
    pub fn spawn(customer_process_port: u16, healthcheck: Option<String>, use_tls: bool) -> Self {
        let default_interval = std::time::Duration::from_secs(1);
        let (user_process_healthcheck_channel, shutdown_notifier) = if use_tls {
            let (agent, channel, shutdown_channel) = HealthcheckAgent::build_tls_agent(
                customer_process_port,
                default_interval,
                healthcheck,
            );
            tokio::spawn(async move { agent.run().await });
            (channel, shutdown_channel)
        } else {
            let (agent, channel, shutdown_channel) =
                HealthcheckAgent::build_agent(customer_process_port, default_interval, healthcheck);
            tokio::spawn(async move { agent.run().await });
            (channel, shutdown_channel)
        };

        Self {
            user_process_healthcheck_channel,
            shutdown_notifier,
        }
    }

    /// Channel used by critical in-Enclave services to notify the agent that they have exited.
    pub fn shutdown_notifier(&self) -> Sender<Service> {
        self.shutdown_notifier.clone()
    }

    /// Read the latest user process health recorded by the agent.
    pub async fn check_user_process_health(&self) -> UserProcessHealth {
        let (request, receiver) = HealthcheckStatusRequest::new();
        if let Err(e) = self.user_process_healthcheck_channel.send(request) {
            return UserProcessHealth::Error(format!(
                "Failed to send healthcheck to user process on channel {e:?}"
            ));
        }

        match receiver.await {
            Ok(health) => health,
            Err(e) => UserProcessHealth::Error(format!(
                "Failed to receive healthcheck from on channel {e:?}"
            )),
        }
    }
}

/// Wire up the Enclave's healthcheck topology - an agent polling the user process, and a server
/// exposing its verdict over the bridge back to the host.
pub async fn build_health_check_server(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
) -> shared::server::error::ServerResult<(HealthcheckServer<BridgeServer>, HealthcheckAgentHandle)>
{
    let agent = HealthcheckAgentHandle::spawn(customer_process_port, healthcheck, use_tls);
    let listener =
        Bridge::get_listener(ENCLAVE_HEALTH_CHECK_PORT, Direction::EnclaveToHost).await?;
    log::info!("Data plane health check server bound to port {ENCLAVE_HEALTH_CHECK_PORT}");
    Ok((HealthcheckServer::new(agent.clone(), listener), agent))
}

/// Serves the Enclave's healthcheck over any accepted transport. The listener is injected so that
/// the same server runs over the bridge in the Enclave and over loopback TCP in tests.
pub struct HealthcheckServer<L: Listener> {
    agent: HealthcheckAgentHandle,
    listener: L,
}

impl<L: Listener> HealthcheckServer<L> {
    pub fn new(agent: HealthcheckAgentHandle, listener: L) -> Self {
        Self { agent, listener }
    }

    pub async fn run(mut self) {
        log::info!("Data plane health check server running");
        loop {
            let stream = match self.listener.accept().await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("Error accepting health check request — {e:?}");
                    continue;
                }
            };

            let agent = self.agent.clone();
            let service = service_fn(move |_| {
                let agent = agent.clone();
                async move {
                    let user_process_health = agent.check_user_process_health().await;

                    let result = DataPlaneState::Initialized(DataPlaneDiagnostic {
                        user_process: user_process_health,
                    });

                    Response::builder()
                        .status(200)
                        .header(header::CONTENT_TYPE, "application/json;version=1")
                        .body(Body::from(serde_json::to_string(&result).unwrap()))
                }
            });

            if let Err(error) = hyper::server::conn::Http::new()
                .http1_only(true)
                .serve_connection(stream, service)
                .await
            {
                log::error!("Data plane health check error: {error}");
            }
        }
    }
}
