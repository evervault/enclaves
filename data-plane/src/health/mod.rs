mod agent;
pub mod diagnostic;

use agent::{DiagnosticReceiver, HealthcheckAgentRequest, HealthcheckAgentSender};

use hyper::header;
use hyper::{service::service_fn, Body, Response};
use shared::server::get_vsock_server;
use shared::server::health::{DataPlaneDiagnostic, DataPlaneState};
use shared::server::CID::Enclave;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};
use thiserror::Error;
use tokio::sync::{mpsc::error::SendError, oneshot::error::RecvError};

#[derive(Error, Debug)]
pub enum HealthCheckAgentChannelErr {
    #[error("Failed to send healthcheck to user process on channel {0}")]
    Send(#[from] SendError<HealthcheckAgentRequest>),
    #[error("Failed to receive healthcheck from on channel {0}")]
    Receive(#[from] RecvError),
}

fn spawn_customer_healthcheck_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
    diag_recv: DiagnosticReceiver,
) -> HealthcheckAgentSender {
    let (agent, healthcheck_channel) =
        agent::default_agent(customer_process_port, healthcheck, diag_recv);
    tokio::spawn(async move {
        log::info!("Spawning healthcheck agent.");
        agent.run().await;
    });
    healthcheck_channel
}

pub async fn start_health_check_server(
    customer_process_port: u16,
    healthcheck: Option<String>,
    diag_recv: DiagnosticReceiver,
) {
    let hc_agent_channel =
        spawn_customer_healthcheck_agent(customer_process_port, healthcheck, diag_recv);
    let mut health_check_server = get_vsock_server(ENCLAVE_HEALTH_CHECK_PORT, Enclave)
        .await
        .unwrap();

    log::info!("Data plane health check server running on port {ENCLAVE_HEALTH_CHECK_PORT}");
    loop {
        let stream = match health_check_server.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                log::error!("Error accepting health check request — {e:?}");
                continue;
            }
        };

        let hc_agent_channel = hc_agent_channel.clone();
        let service = service_fn(move |_| {
            let hc_agent_channel = hc_agent_channel.clone();
            async move {
                let dp_diagnostic = recv_diagnostic_from_agent(&hc_agent_channel).await;

                let result = match dp_diagnostic {
                    Ok(diag) => DataPlaneState::Initialized(diag),
                    Err(e) => {
                        DataPlaneState::Error(format!("Failed to get diagnostic from agent: {e}"))
                    }
                };

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

async fn recv_diagnostic_from_agent(
    channel: &HealthcheckAgentSender,
) -> Result<DataPlaneDiagnostic, HealthCheckAgentChannelErr> {
    let (request, receiver) = HealthcheckAgentRequest::new();
    channel.send(request)?;

    Ok(receiver.await?)
}
