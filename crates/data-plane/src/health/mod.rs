mod agent;

use agent::UserProcessHealthcheckSender;

use hyper::header;
use hyper::{service::service_fn, Body, Request, Response};
use shared::bridge::{Bridge, BridgeInterface, BridgeServer, Direction};
use shared::notify_shutdown::Service;
use shared::server::health::{
    DataPlaneDiagnostic, DataPlaneHealth, DataPlaneState, HealthCheckFormat, UserProcessHealth,
};
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};
use tokio::sync::mpsc::Sender;

use crate::health::agent::{HealthcheckAgent, HealthcheckStatusRequest};
use crate::launcher::BootJournal;

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
///
/// `boot_journal` is the read handle the server consults on each request. Whoever drives the boot
/// sequence registers a clone of the same journal as a boot observer, so a warning raised by a
/// stage reaches the next healthcheck body with no further plumbing.
pub async fn build_health_check_server(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
    boot_journal: BootJournal,
) -> shared::server::error::ServerResult<(HealthcheckServer<BridgeServer>, HealthcheckAgentHandle)>
{
    let agent = HealthcheckAgentHandle::spawn(customer_process_port, healthcheck, use_tls);
    let listener =
        Bridge::get_listener(ENCLAVE_HEALTH_CHECK_PORT, Direction::EnclaveToHost).await?;
    log::info!("Data plane health check server bound to port {ENCLAVE_HEALTH_CHECK_PORT}");
    Ok((
        HealthcheckServer::new(agent.clone(), listener, boot_journal),
        agent,
    ))
}

/// Serves the Enclave's healthcheck over any accepted transport. The listener is injected so that
/// the same server runs over the bridge in the Enclave and over loopback TCP in tests.
pub struct HealthcheckServer<L: Listener> {
    agent: HealthcheckAgentHandle,
    listener: L,
    boot_journal: BootJournal,
}

impl<L: Listener> HealthcheckServer<L> {
    pub fn new(agent: HealthcheckAgentHandle, listener: L, boot_journal: BootJournal) -> Self {
        Self {
            agent,
            listener,
            boot_journal,
        }
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
            let boot_journal = self.boot_journal.clone();
            let service = service_fn(move |request: Request<Body>| {
                let agent = agent.clone();
                let boot_journal = boot_journal.clone();
                // Read before the request is dropped, and answered in the caller's format rather
                // than the newest one this data plane knows. The caller names what it can read;
                // a body it did not ask for it cannot parse, and an unparseable body reads to the
                // host as an Enclave that cannot be reached at all.
                let format = HealthCheckFormat::from_accept(
                    request
                        .headers()
                        .get(header::ACCEPT)
                        .and_then(|accept| accept.to_str().ok()),
                );

                async move {
                    let user_process_health = agent.check_user_process_health().await;

                    // Built once, in the format that can hold everything, then downgraded if the
                    // caller reads an older one. The boot report is context attached to the
                    // verdict, never part of it: the status code below stays 200 whatever boot
                    // recorded.
                    let health = DataPlaneHealth::new(DataPlaneState::Initialized(
                        DataPlaneDiagnostic::new(user_process_health),
                    ))
                    .with_boot(boot_journal.report());

                    let body = match format {
                        HealthCheckFormat::V1 => {
                            serde_json::to_string(&DataPlaneState::from(health))
                        }
                        HealthCheckFormat::V2 => serde_json::to_string(&health),
                    };

                    Response::builder()
                        .status(200)
                        .header(header::CONTENT_TYPE, format.content_type())
                        .body(Body::from(body.unwrap()))
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
