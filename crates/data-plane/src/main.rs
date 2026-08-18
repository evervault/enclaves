use std::future::Future;

#[cfg(feature = "network_egress")]
use data_plane::dns::{egressproxy::EgressProxy, enclavedns::EnclaveDnsProxy};
use data_plane::{
    configuration,
    crypto::api::CryptoApi,
    env::{init_environment_loader, EnvironmentLoader},
    health::{build_health_check_server, HealthcheckServer},
    launcher::BootJournal,
    stats::{client::StatsClient, proxy::StatsProxy},
    time::ClockSync,
    FeatureContext,
};
use shared::server::Listener;
use shared::{
    bridge::{Bridge, BridgeInterface, Direction},
    notify_shutdown::{NotifyShutdown, Service},
    print_version, ENCLAVE_CONNECT_PORT,
};
use tokio::sync::mpsc::Sender;
use tokio::time::Duration;

#[cfg(feature = "enclave")]
fn try_show_fd_limits() {
    if let Ok((soft_limit, hard_limit)) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
        println!("RLIMIT_NOFILE: SoftLimit={soft_limit}, HardLimit={hard_limit}");
    }
}

#[cfg(feature = "enclave")]
fn apply_clamped_limit() {
    if let Err(e) = rlimit::increase_nofile_limit(rlimit::INFINITY) {
        eprintln!("Failed to clamp softlimit to proc hardlimit - {e}")
    }
}

#[cfg(feature = "enclave")]
fn try_update_fd_limit() {
    let sys_fd_lim = std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let Some(nr_open) = sys_fd_lim else {
        apply_clamped_limit();
        return;
    };

    if let Err(e) = rlimit::setrlimit(rlimit::Resource::NOFILE, nr_open, nr_open) {
        eprintln!(
            "Failed to set enclave file descriptor limit on startup (requested {nr_open}) - {e:?}"
        );
        apply_clamped_limit();
    };
}

const ENCLAVE_CLOCK_SYNC_INTERVAL: Duration = Duration::from_secs(300);

fn main() {
    shared::logging::init_env_logger();
    print_version!("Data Plane");

    #[cfg(feature = "enclave")]
    {
        try_update_fd_limit();
        try_show_fd_limits();
    }

    let data_plane_port =
        configuration::parse_target_port_from_args().unwrap_or(configuration::DEFAULT_TARGET_PORT);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime in data plane");

    let ctx = match FeatureContext::initialize() {
        Ok(ctx) => ctx,
        Err(e) => {
            log::error!("Failed to initialize context in enclave, cannot proceed - {e:?}");
            return;
        }
    };

    runtime.block_on(async move {
        // One journal, shared: the healthcheck server reads it, and the boot sequence records
        // into this handle once its observers are registered.
        let boot_journal = BootJournal::default();
        let Ok((health_check_server, healthcheck_agent_handle)) = build_health_check_server(
            ctx.healthcheck_port.unwrap_or(data_plane_port),
            ctx.healthcheck,
            ctx.healthcheck_use_tls.unwrap_or(false),
            boot_journal.clone(),
        )
        .await
        else {
            log::error!("Failed to launch in-Enclave healthcheck service, exiting early.");
            return;
        };

        launch_service_with_healthcheck(
            health_check_server,
            healthcheck_agent_handle.shutdown_notifier(),
            |shutdown_notifier: Sender<Service>| start(data_plane_port, shutdown_notifier),
        )
        .await;
    });
}

/// Run the Enclave's boot sequence alongside the in-Enclave healthcheck server.
///
/// The health check server owns the process's lifetime. It must stay up and reachable even if the
/// boot sequence fails, so that the failure is reported as unhealthy rather than masked by a
/// process exit + supervisor restart. `svc` is expected to run for the lifetime of the Enclave, so
/// any exit of the boot task (clean, panicking, or cancelled) is reported to the healthcheck
/// agent through the shutdown_notifier.
async fn launch_service_with_healthcheck<L, Fut, F>(
    health_check_server: HealthcheckServer<L>,
    shutdown_notifier: Sender<Service>,
    svc: F,
) where
    L: Listener,
    Fut: Future<Output = ()> + Send + 'static,
    F: FnOnce(Sender<Service>) -> Fut,
{
    let boot_notifier = shutdown_notifier.clone();
    let start_handle = tokio::spawn(svc(shutdown_notifier));
    tokio::spawn(async move {
        match start_handle.await {
            Ok(()) => log::error!("Data-plane boot task exited unexpectedly"),
            Err(e) => log::error!("Data-plane boot task exited abnormally - {e:?}"),
        }
        // The boot task exiting at all leaves the Enclave without its critical services, so notify
        // the agent regardless of how it exited.
        let _ = boot_notifier.try_send(Service::EnvironmentLoader);
    });

    health_check_server.run().await;
}

async fn start(data_plane_port: u16, shutdown_notifier: Sender<Service>) {
    if let Err(e) = StatsClient::init().await {
        log::error!("Failed to register in-Enclave stats client - {e}");
    }
    let context = match FeatureContext::get() {
        Ok(context) => context,
        Err(e) => {
            log::error!("Failed to access context in enclave - {e}");
            return;
        }
    };

    if cfg!(not(feature = "network_egress")) {
        log::info!("Running data plane with egress disabled");
    } else {
        log::info!("Running data plane with egress enabled");
    }

    let env_loader = init_environment_loader();
    let env_loader = match env_loader.load_env_vars().await {
        Ok(env_loader) => env_loader,
        Err(e) => {
            log::error!("An error occurred initializing the enclave environment - {e:?}");
            let _ = shutdown_notifier.try_send(Service::EnvironmentLoader);
            return;
        }
    };

    // Schedule non-critical stats proxy
    tokio::spawn(async move {
        if let Err(e) = StatsProxy::listen().await {
            log::error!("In-Enclave Stats proxy exited with an error - {e}");
        }
    });

    // Schedule critical services with notify shutdown futures to ensure healthchecks detect any single critical failure.
    tokio::spawn(
        CryptoApi::listen().notify_shutdown(Service::CryptoApi, shutdown_notifier.clone()),
    );
    tokio::spawn(
        ClockSync::run(ENCLAVE_CLOCK_SYNC_INTERVAL)
            .notify_shutdown(Service::ClockSync, shutdown_notifier.clone()),
    );

    #[cfg(feature = "network_egress")]
    {
        tokio::spawn(
            EnclaveDnsProxy::bind_server(context.egress.allow_list.clone())
                .notify_shutdown(Service::DnsProxy, shutdown_notifier.clone()),
        );
        tokio::spawn(
            EgressProxy::listen().notify_shutdown(Service::EgressProxy, shutdown_notifier.clone()),
        );
    }

    start_data_plane(data_plane_port, context, env_loader)
        .notify_shutdown(Service::DataPlane, shutdown_notifier.clone())
        .await;
}

#[cfg(feature = "tls_termination")]
use data_plane::env::NeedCert;
#[cfg(feature = "tls_termination")]
async fn start_data_plane(
    data_plane_port: u16,
    context: FeatureContext,
    env_loader: EnvironmentLoader<NeedCert>,
) {
    log::info!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let server = match Bridge::get_listener(ENCLAVE_CONNECT_PORT, Direction::EnclaveToHost).await {
        Ok(server) => server,
        Err(error) => return log::error!("Error creating server: {error}"),
    };
    log::debug!("Data plane TCP server created");

    log::info!("TLS Termination enabled in dataplane. Running tls server.");
    if let Err(e) =
        data_plane::server::server::run(server, data_plane_port, context, env_loader).await
    {
        log::error!("Failed to run data plane - {e}");
    }
}

#[cfg(not(feature = "tls_termination"))]
use data_plane::env::Finalize;
#[cfg(not(feature = "tls_termination"))]
use shared::{
    server::proxy_protocol::{ProxiedConnection, ProxyProtocolServer},
    utils::pipe_streams,
};
#[cfg(not(feature = "tls_termination"))]
use tokio::io::AsyncWriteExt;
#[cfg(not(feature = "tls_termination"))]
async fn start_data_plane(
    data_plane_port: u16,
    context: FeatureContext,
    env_loader: EnvironmentLoader<Finalize>,
) {
    log::info!("Data plane starting up. Forwarding traffic to {data_plane_port}");
    let mut server =
        match Bridge::get_listener(ENCLAVE_CONNECT_PORT, Direction::EnclaveToHost).await {
            Ok(server) => ProxyProtocolServer::from(server),
            Err(error) => return log::error!("Error creating server: {error}"),
        };
    log::debug!("Data plane TCP server created");
    if let Err(e) = env_loader.finalize_env() {
        log::error!("Errored while finalizing environment - {e:?}");
        return;
    }

    log::info!("Piping TCP streams directly to user process");

    loop {
        let incoming_conn = match server.accept().await {
            Ok(incoming_conn) => incoming_conn,
            Err(e) => {
                log::error!(
                    "An error occurred while accepting the incoming connection — {}",
                    e
                );
                continue;
            }
        };

        tokio::spawn(async move {
            let mut customer_stream =
                match tokio::net::TcpStream::connect(("0.0.0.0", data_plane_port)).await {
                    Ok(customer_stream) => customer_stream,
                    Err(e) => {
                        log::error!(
                            "An error occurred while connecting to the customer process — {}",
                            e
                        );
                        return;
                    }
                };

            if incoming_conn.has_proxy_protocol() && context.forward_proxy_protocol {
                // flush proxy protocol bytes to customer process
                let proxy_protocol = incoming_conn.proxy_protocol().unwrap();
                if let Err(e) = customer_stream.write_all(proxy_protocol.as_bytes()).await {
                    log::error!(
                      "An error occurred while forwarding the proxy protocol to the customer process — {}",
                      e
                  );
                    return;
                }
            }

            if let Err(e) = pipe_streams(incoming_conn, customer_stream).await {
                log::error!("An error occurred piping between the incoming connection and the customer process — {}", e);
                return;
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::launch_service_with_healthcheck;
    use data_plane::health::{HealthcheckAgentHandle, HealthcheckServer};
    use data_plane::launcher::{
        BootChain, BootContext, BootError, BootJournal, Diagnostic, LogObserver, Observers, Stage,
    };
    use hyper::{header, Body, Request};
    use shared::notify_shutdown::{NotifyShutdown, Service};
    use shared::server::health::{
        DataPlaneDiagnostic, DataPlaneHealth, DataPlaneState, HealthCheck, HealthCheckFormat,
        UserProcessHealth,
    };
    use shared::server::TcpServer;
    use std::future::{pending, Future};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc::Sender;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::Duration;

    /// Matches the interval that `HealthcheckAgentHandle::spawn` gives the agent.
    const AGENT_INTERVAL: Duration = Duration::from_secs(1);
    /// Number of agent intervals a test will drive the paused clock through before giving up.
    const MAX_AGENT_TICKS: usize = 5;

    /// Spawn an agent with no healthcheck path so that its verdict is driven purely by the shutdown
    /// notifications it receives, rather than by probing a user process which isn't running here.
    fn spawn_healthcheck_agent() -> HealthcheckAgentHandle {
        HealthcheckAgentHandle::spawn(3000, None, false)
    }

    /// A running `launch_service_with_healthcheck` backed by a live healthcheck server on loopback.
    /// `Drop` aborts the launcher, which never returns of its own accord.
    struct TestLaunch {
        agent: HealthcheckAgentHandle,
        /// The journal the healthcheck server exports. Recording into it here is what a boot stage
        /// does in the Enclave.
        boot_journal: BootJournal,
        /// Where the healthcheck server is listening, so that a test can read the serialized body
        /// rather than the agent's in-process verdict.
        address: SocketAddr,
        handle: JoinHandle<()>,
    }

    impl Drop for TestLaunch {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    /// Launch `svc` behind the real healthcheck server, bound to an ephemeral loopback port. The
    /// launcher has to be spawned rather than awaited, because a real healthcheck server loops on
    /// `accept` forever. This is the property that we are testing.
    async fn spawn_launch<Fut, F>(svc: F) -> TestLaunch
    where
        Fut: Future<Output = ()> + Send + 'static,
        F: FnOnce(Sender<Service>) -> Fut + Send + 'static,
    {
        let agent = spawn_healthcheck_agent();
        let boot_journal = BootJournal::default();
        let listener = TcpServer::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind healthcheck test listener");
        let address = listener
            .local_addr()
            .expect("Failed to read the healthcheck test listener's address");
        let handle = tokio::spawn(launch_service_with_healthcheck(
            HealthcheckServer::new(agent.clone(), listener, boot_journal.clone()),
            agent.shutdown_notifier(),
            svc,
        ));
        TestLaunch {
            agent,
            boot_journal,
            address,
            handle,
        }
    }

    /// The launcher must outlive the boot sequence. If this assertions fails, it indicates that
    /// the process exits on a boot sequence failure. This would be masked in production through
    /// a supervisor restart instead of being reported.
    fn assert_still_serving_healthchecks(launch: &TestLaunch) {
        assert!(
            !launch.handle.is_finished(),
            "Healthcheck server stopped serving — the failure would be masked by a process exit"
        );
    }

    /// Drive the paused clock forward an interval at a time, giving the agent a chance to perform a
    /// healthcheck and drain any pending shutdown notifications. Returns the health reported by the
    /// agent as soon as it goes unhealthy, or `None` if it stayed healthy for every tick.
    async fn health_once_agent_reports_error(
        agent: &HealthcheckAgentHandle,
    ) -> Option<UserProcessHealth> {
        for _ in 0..MAX_AGENT_TICKS {
            tokio::task::yield_now().await;
            tokio::time::advance(AGENT_INTERVAL).await;
            let health = agent.check_user_process_health().await;
            if health.is_error() {
                return Some(health);
            }
        }
        None
    }

    fn assert_error_names_service(health: Option<UserProcessHealth>, service: Service) {
        let Some(UserProcessHealth::Error(message)) = health else {
            panic!("Expected the healthcheck agent to report an error, got - {health:?}");
        };
        assert!(
            message.contains(&service.to_string()),
            "Expected the healthcheck error to name the {service} service, got - {message}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn it_remains_healthy_while_the_service_is_online() {
        // A service which never returns, mirroring an Enclave whose critical services are all up.
        let launch = spawn_launch(|_| pending()).await;

        for _ in 0..MAX_AGENT_TICKS {
            tokio::task::yield_now().await;
            tokio::time::advance(AGENT_INTERVAL).await;
            let health = launch.agent.check_user_process_health().await;
            assert!(
                !health.is_error(),
                "Healthcheck agent reported an error while the service was online - {health:?}"
            );
            assert!(
                DataPlaneDiagnostic::new(health).is_healthy(),
                "Enclave reported itself unhealthy while the service was online"
            );
        }

        assert_still_serving_healthchecks(&launch);
    }

    #[tokio::test(start_paused = true)]
    async fn it_reports_unhealthy_when_the_service_exits_and_notifies_shutdown() {
        // Mirrors how `start` wraps its critical services, so the exiting service is named.
        let launch = spawn_launch(|shutdown_notifier: Sender<Service>| {
            async {}.notify_shutdown(Service::DataPlane, shutdown_notifier)
        })
        .await;

        let health = health_once_agent_reports_error(&launch.agent).await;
        assert_error_names_service(health, Service::DataPlane);
        assert_still_serving_healthchecks(&launch);
    }

    #[tokio::test(start_paused = true)]
    async fn it_reports_unhealthy_when_the_service_exits_without_notifying_shutdown() {
        // A boot sequence which returns early without reporting the failure itself - the launcher
        // is responsible for surfacing it, otherwise the Enclave reports healthy while running
        // none of its critical services.
        let launch = spawn_launch(|_| async {}).await;

        let health = health_once_agent_reports_error(&launch.agent).await;
        assert_error_names_service(health, Service::EnvironmentLoader);
        assert_still_serving_healthchecks(&launch);
    }

    #[tokio::test(start_paused = true)]
    async fn it_reports_unhealthy_when_the_service_panics() {
        let launch = spawn_launch(|_| async {
            panic!("Intentional panic in the data plane boot sequence");
        })
        .await;

        let health = health_once_agent_reports_error(&launch.agent).await;
        assert_error_names_service(health, Service::EnvironmentLoader);
        assert_still_serving_healthchecks(&launch);
    }

    #[tokio::test(start_paused = true)]
    async fn it_keeps_serving_healthchecks_after_the_service_panics() {
        let (trigger_panic, panic_signal) = oneshot::channel::<()>();

        let launch = spawn_launch(|_| async move {
            let _ = panic_signal.await;
            panic!("Intentional panic in the data plane after coming online");
        })
        .await;

        // The Enclave is healthy while the service is online...
        tokio::task::yield_now().await;
        tokio::time::advance(AGENT_INTERVAL).await;
        let health = launch.agent.check_user_process_health().await;
        assert!(
            !health.is_error(),
            "Healthcheck agent reported an error before the service panicked - {health:?}"
        );

        // ...and reports unhealthy once it panics, rather than exiting the process.
        trigger_panic
            .send(())
            .expect("Data plane service dropped its panic signal");
        let health = health_once_agent_reports_error(&launch.agent).await;
        assert_error_names_service(health, Service::EnvironmentLoader);
        assert_still_serving_healthchecks(&launch);
    }

    /// Stands in for a real boot stage: it records as it goes, and either succeeds or fails. The
    /// label is a real stage name so that the body under test reads the way a production one will.
    struct LoadEnvironment {
        fail: bool,
    }

    impl Stage for LoadEnvironment {
        type In = ();
        type Out = ();
        type Error = std::io::Error;

        const LABEL: &'static str = "load-environment";
        const BLAME: Service = Service::EnvironmentLoader;

        async fn run(self, ctx: &BootContext, _input: Self::In) -> Result<Self::Out, Self::Error> {
            ctx.record(Diagnostic::info(
                "env.secrets-decrypted",
                "decrypted 4 environment variables",
            ));
            ctx.record(Diagnostic::warn(
                "env.malformed-variable-dropped",
                "dropped 1 malformed environment variable",
            ));

            if self.fail {
                Err(std::io::Error::other(
                    "could not write the environment file",
                ))
            } else {
                Ok(())
            }
        }
    }

    /// Run a boot chain against the journal the launch's healthcheck server is exporting, through
    /// the same observer fan-out the Enclave registers.
    async fn run_boot_chain(launch: &TestLaunch, fail: bool) -> Result<(), BootError> {
        let observers = Observers::new(vec![
            Box::new(LogObserver),
            Box::new(launch.boot_journal.clone()),
        ]);
        let boot_context = BootContext::new(Arc::new(observers), launch.agent.shutdown_notifier());

        BootChain::seed(boot_context, ())
            .then(LoadEnvironment { fail })
            .run()
            .await
    }

    /// A healthcheck response as the host sees it. Everything below asserts against the serialized
    /// body rather than the agent's in-process verdict, because the body is what crosses the bridge.
    struct HealthResponse {
        status_code: u16,
        content_type: Option<String>,
        body: String,
    }

    /// Poll the healthcheck the way the host does.
    ///
    /// `accept` names the formats the caller understands. `None` is not a placeholder: it is what a
    /// caller predating format negotiation sends, and the case the default exists to serve.
    async fn get_health(launch: &TestLaunch, accept: Option<String>) -> HealthResponse {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("http://{}/", launch.address));
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }

        let response = hyper::Client::new()
            .request(
                request
                    .body(Body::empty())
                    .expect("Failed to build the healthcheck test request"),
            )
            .await
            .expect("Failed to reach the healthcheck server");

        let status_code = response.status().as_u16();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = hyper::body::to_bytes(response.into_body())
            .await
            .expect("Failed to read the healthcheck response body");

        HealthResponse {
            status_code,
            content_type,
            body: String::from_utf8(body.to_vec()).expect("The healthcheck body should be UTF-8"),
        }
    }

    /// Read a response as v1, asserting it was served as v1 on the way.
    fn expect_v1(response: &HealthResponse) -> DataPlaneState {
        assert_eq!(
            response.content_type.as_deref(),
            Some(HealthCheckFormat::V1.content_type())
        );

        serde_json::from_str(&response.body)
            .expect("Failed to deserialize the healthcheck response")
    }

    fn expect_initialized(state: DataPlaneState) -> DataPlaneDiagnostic {
        match state {
            DataPlaneState::Initialized(diagnostic) => diagnostic,
            other => panic!("Expected an initialized data plane, got - {other:?}"),
        }
    }

    /// Read a response as v2, asserting it was served as v2 on the way.
    fn expect_v2(response: &HealthResponse) -> DataPlaneHealth {
        assert_eq!(
            response.content_type.as_deref(),
            Some(HealthCheckFormat::V2.content_type())
        );

        serde_json::from_str(&response.body)
            .expect("Failed to deserialize the healthcheck response")
    }

    /// A caller that names no format is served v1, unchanged. This is the rarer skew — a freshly
    /// built Enclave polled by a control plane that has not rolled forward — but it is the one the
    /// default exists for, since such a caller cannot parse anything it did not ask for.
    ///
    /// Boot diagnostics are a v2 addition, so this body is the one the Enclave has always served
    /// even with warnings recorded. Asserting it whole is what pins that.
    #[tokio::test]
    async fn it_serves_the_unchanged_v1_body_to_a_caller_that_names_no_format() {
        // A service which never returns, mirroring an Enclave whose critical services are all up.
        let launch = spawn_launch(|_| pending()).await;

        run_boot_chain(&launch, false)
            .await
            .expect("The boot chain should have succeeded");

        let response = get_health(&launch, None).await;
        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.content_type.as_deref(),
            Some(HealthCheckFormat::V1.content_type())
        );
        assert_eq!(
            response.body,
            r#"{"Initialized":{"user_process":{"Unknown":"Enclave is not initialized yet"}}}"#
        );

        assert_still_serving_healthchecks(&launch);
    }

    /// A caller that names only v1 is served v1, even though this data plane can serve more.
    #[tokio::test]
    async fn it_serves_v1_to_a_caller_that_names_only_v1() {
        let launch = spawn_launch(|_| pending()).await;

        let response = get_health(
            &launch,
            Some(HealthCheckFormat::V1.content_type().to_string()),
        )
        .await;

        assert_eq!(
            response.content_type.as_deref(),
            Some(HealthCheckFormat::V1.content_type())
        );
    }

    /// v2 puts the boot report beside the state, so a consumer reads what boot saw without having
    /// to reach through `Initialized` — and without the data plane having reached it.
    #[tokio::test]
    async fn it_serves_boot_warnings_beside_the_state_to_a_caller_that_asks_for_v2() {
        let launch = spawn_launch(|_| pending()).await;

        run_boot_chain(&launch, false)
            .await
            .expect("The boot chain should have succeeded");

        let response = get_health(&launch, Some(HealthCheckFormat::accept_header())).await;
        assert_eq!(response.status_code, 200);

        let health = expect_v2(&response);
        // A boot warning is context for an operator, never a verdict.
        assert!(
            health.is_healthy(),
            "A boot warning flipped the Enclave's health verdict"
        );
        assert_eq!(health.status_code(), 200);

        let diagnostic = expect_initialized(health.state);
        assert_eq!(
            diagnostic.user_process,
            UserProcessHealth::Unknown("Enclave is not initialized yet".to_string())
        );

        // No stage is in flight once the chain has run to completion.
        assert_eq!(health.boot.stage, None);
        // Only the warning is exported. The informational diagnostic stops at the log.
        assert_eq!(health.boot.diagnostics.len(), 1);
        assert_eq!(health.boot.diagnostics[0].stage, "load-environment");
        assert_eq!(
            health.boot.diagnostics[0].code,
            "env.malformed-variable-dropped"
        );
        assert_eq!(
            health.boot.diagnostics[0].message,
            "dropped 1 malformed environment variable"
        );
        assert_eq!(health.boot.dropped, 0);

        assert_still_serving_healthchecks(&launch);
    }

    #[tokio::test]
    async fn it_names_the_failing_stage_to_a_caller_that_asks_for_v2() {
        let launch = spawn_launch(|_| pending()).await;

        let error = run_boot_chain(&launch, true)
            .await
            .expect_err("The boot chain should have surfaced the stage's failure");
        assert!(matches!(error, BootError::Io(_)));

        let response = get_health(&launch, Some(HealthCheckFormat::accept_header())).await;
        assert_eq!(response.status_code, 200);

        let health = expect_v2(&response);
        // The report goes on naming the stage that broke, and keeps what it recorded on the way.
        assert_eq!(health.boot.stage.as_deref(), Some("load-environment"));
        assert_eq!(health.boot.diagnostics.len(), 1);
        assert_eq!(
            health.boot.diagnostics[0].code,
            "env.malformed-variable-dropped"
        );

        assert_still_serving_healthchecks(&launch);
    }

    /// The two formats describe one reading of one Enclave. v2 wraps the state v1 serves rather
    /// than restating it, and this is what holds it to that.
    #[tokio::test]
    async fn both_formats_report_the_same_state() {
        let launch = spawn_launch(|_| pending()).await;

        run_boot_chain(&launch, false)
            .await
            .expect("The boot chain should have succeeded");

        let v1 = get_health(&launch, None).await;
        let v2 = get_health(&launch, Some(HealthCheckFormat::accept_header())).await;

        let v1_state = expect_v1(&v1);
        let v2_health = expect_v2(&v2);

        assert_eq!(v1_state.status_code(), v2_health.status_code());
        assert_eq!(v1_state.is_healthy(), v2_health.is_healthy());
        assert_eq!(
            expect_initialized(v1_state).user_process,
            expect_initialized(v2_health.state).user_process
        );
    }
}
