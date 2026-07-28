mod agent;

use agent::UserProcessHealthcheckSender;
pub use agent::{Attesting, BootProgress, Provisioning, SourcingTlsCerts};

use hyper::header;
use hyper::{service::service_fn, Body, Response};
use shared::bridge::{Bridge, BridgeInterface, BridgeServer, Direction};
use shared::notify_shutdown::Service;
use shared::server::health::DataPlaneState;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};
use tokio::sync::mpsc::{Sender, UnboundedSender};

use crate::health::agent::{HealthcheckAgent, HealthcheckStatusRequest};

fn spawn_customer_healthcheck_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
) -> (
    UserProcessHealthcheckSender,
    Sender<Service>,
    BootProgress<Provisioning>,
) {
    let default_interval = std::time::Duration::from_secs(1);
    if use_tls {
        let (agent, channel, shutdown_channel, boot_progress) =
            HealthcheckAgent::build_tls_agent(customer_process_port, default_interval, healthcheck);
        tokio::spawn(async move { agent.run().await });
        (channel, shutdown_channel, boot_progress)
    } else {
        let (agent, channel, shutdown_channel, boot_progress) =
            HealthcheckAgent::build_agent(customer_process_port, default_interval, healthcheck);
        tokio::spawn(async move { agent.run().await });
        (channel, shutdown_channel, boot_progress)
    }
}

pub async fn build_health_check_server(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
) -> shared::server::error::ServerResult<(
    HealthcheckServer,
    Sender<Service>,
    BootProgress<Provisioning>,
)> {
    let (user_process_healthcheck_channel, shutdown_notifier, boot_phase_notifier) =
        spawn_customer_healthcheck_agent(customer_process_port, healthcheck, use_tls);
    let health_check_server = HealthcheckServer::new(user_process_healthcheck_channel).await?;
    Ok((health_check_server, shutdown_notifier, boot_phase_notifier))
}

pub struct HealthcheckServer {
    user_process_healthcheck_channel: UnboundedSender<HealthcheckStatusRequest>,
    listener: BridgeServer,
}

impl HealthcheckServer {
    async fn new(
        user_process_healthcheck_channel: UnboundedSender<HealthcheckStatusRequest>,
    ) -> shared::server::error::ServerResult<Self> {
        let listener =
            Bridge::get_listener(ENCLAVE_HEALTH_CHECK_PORT, Direction::EnclaveToHost).await?;
        Ok(Self {
            listener,
            user_process_healthcheck_channel,
        })
    }

    pub async fn run(mut self) {
        log::info!("Data plane health check server running on port {ENCLAVE_HEALTH_CHECK_PORT}");
        loop {
            let stream = match self.listener.accept().await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("Error accepting health check request — {e:?}");
                    continue;
                }
            };

            let user_process_channel = self.user_process_healthcheck_channel.clone();
            let service = service_fn(move |_| {
                let user_process_channel = user_process_channel.clone();
                async move {
                    let result = get_data_plane_state(&user_process_channel).await;

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

async fn get_data_plane_state(channel: &UserProcessHealthcheckSender) -> DataPlaneState {
    let (request, receiver) = HealthcheckStatusRequest::new();
    if let Err(e) = channel.send(request) {
        return DataPlaneState::Error(format!(
            "Failed to send healthcheck request to agent on channel {e:?}"
        ));
    }

    match receiver.await {
        Ok(state) => state,
        Err(e) => DataPlaneState::Error(format!(
            "Failed to receive healthcheck from agent on channel {e:?}"
        )),
    }
}
