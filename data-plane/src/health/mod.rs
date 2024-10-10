mod agent;

use agent::UserProcessHealthcheckSender;

use hyper::header;
use hyper::{service::service_fn, Body, Response};
use shared::server::get_vsock_server;
use shared::server::health::{DataPlaneDiagnostic, DataPlaneState, UserProcessHealth};
use shared::server::CID::Enclave;
use shared::{server::Listener, ENCLAVE_HEALTH_CHECK_PORT};

use crate::health::agent::{HealthcheckAgent, HealthcheckStatusRequest};

fn spawn_customer_healthcheck_agent(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
) -> UserProcessHealthcheckSender {
    let default_interval = std::time::Duration::from_secs(1);
    if use_tls {
        let (agent, channel) =
            HealthcheckAgent::build_tls_agent(customer_process_port, default_interval, healthcheck);
        tokio::spawn(async move { agent.run().await });
        channel
    } else {
        let (agent, channel) =
            HealthcheckAgent::build_agent(customer_process_port, default_interval, healthcheck);
        tokio::spawn(async move { agent.run().await });
        channel
    }
}

pub async fn start_health_check_server(
    customer_process_port: u16,
    healthcheck: Option<String>,
    use_tls: bool,
) {
    let user_process_healthcheck_channel =
        spawn_customer_healthcheck_agent(customer_process_port, healthcheck, use_tls);
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

async fn check_user_process_health(channel: &UserProcessHealthcheckSender) -> UserProcessHealth {
    let (request, receiver) = HealthcheckStatusRequest::new();
    if let Err(e) = channel.send(request) {
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
