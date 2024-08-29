mod agent;
mod initialized;

use agent::UserProcessHealthcheckSender;

use hyper::{service::service_fn, Body, Response};
use shared::server::get_vsock_server;
use shared::server::health::{HealthCheckLog, HealthCheckStatus};
use shared::server::CID::Enclave;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};

use crate::health::agent::HealthcheckStatusRequest;

fn spawn_customer_healthcheck_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
) -> UserProcessHealthcheckSender {
    let (agent, healthcheck_channel) = agent::default_agent(customer_process_port, healthcheck);
    tokio::spawn(async move {
        log::info!("Spawning healthcheck agent.");
        agent.run().await;
    });
    healthcheck_channel
}

pub async fn start_health_check_server(customer_process_port: u16, healthcheck: Option<String>) {
    let user_process_healthcheck_channel =
        spawn_customer_healthcheck_agent(customer_process_port, healthcheck);
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

        let user_process_channel = user_process_healthcheck_channel.clone();
        let service = service_fn(move |_| {
            let user_process_channel = user_process_channel.clone();
            async move {
                let user_process_health = check_user_process_health(&user_process_channel).await;

                Response::builder()
                    .status(user_process_health.status_code())
                    .body(Body::from(
                        serde_json::to_string(&user_process_health).unwrap(),
                    ))
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

async fn check_user_process_health(channel: &UserProcessHealthcheckSender) -> HealthCheckLog {
    let (request, receiver) = HealthcheckStatusRequest::new();
    if let Err(e) = channel.send(request) {
        return HealthCheckLog {
            message: Some(format!("Failed to send healthcheck to user process - {e}")),
            status: HealthCheckStatus::Err,
        };
    }

    match receiver.await {
        Ok(status) => HealthCheckLog {
            status,
            message: None,
        },
        Err(e) => HealthCheckLog {
            status: HealthCheckStatus::Err,
            message: Some(format!(
                "Failed to receive healthcheck response from agent - {e}"
            )),
        },
    }
}
