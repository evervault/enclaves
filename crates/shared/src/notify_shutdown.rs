use std::future::Future;
use std::task::ready;
use tokio::sync::mpsc::Sender;

/// Enum covering all critical internal services within the Enclave. This is used to reportunexpected shutdowns of services in the Enclave.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Service {
    DataPlane,
    CryptoApi,
    ClockSync,
    DnsProxy,
    EgressProxy,
    E3Proxy,
    ProvisionerProxy,
    AcmeProxy,
    ConfigServer,
    EnvironmentLoader,
    StatsClient,
    TlsCerts,
    TrustedCert,
    EnvFinalize,
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let service_label = match self {
            Self::DataPlane => "data-plane",
            Self::CryptoApi => "crypto-api",
            Self::ClockSync => "clock-sync",
            Self::DnsProxy => "dns-proxy",
            Self::EgressProxy => "egress-proxy",
            Self::E3Proxy => "e3-proxy",
            Self::ProvisionerProxy => "provisioner-proxy",
            Self::AcmeProxy => "acme-proxy",
            Self::ConfigServer => "config-server",
            Self::EnvironmentLoader => "environment-loader",
            Self::StatsClient => "stats-client",
            Self::TlsCerts => "tls-certs",
            Self::TrustedCert => "trusted-cert",
            Self::EnvFinalize => "env-finalize",
        };
        f.write_str(service_label)
    }
}

/// The notify shutdown service trait is used to support shutdown notifications of any critical service running within the Enclave.
/// Any future that is converted into a `NotifyShutdownFuture` will send a message containing the service label to the shutdown channel,
/// allowing the healthcheck agent to move the Enclave into a draining state.
///
/// Note: all critical services are assumed to run indefinitely. If one exits, it's assumed that the Enclave is entering an unhealthy state.
pub trait NotifyShutdown: Future {
    fn notify_shutdown(
        self,
        service: Service,
        shutdown_channel: Sender<Service>,
    ) -> NotifyShutdownFuture<Self>
    where
        Self: Sized,
    {
        NotifyShutdownFuture {
            inner: self,
            service,
            shutdown_channel,
        }
    }
}

impl<F: ?Sized> NotifyShutdown for F where F: Future {}

#[pin_project::pin_project]
pub struct NotifyShutdownFuture<F: Future> {
    #[pin]
    inner: F,
    service: Service,
    shutdown_channel: Sender<Service>,
}

impl<F: Future> Future for NotifyShutdownFuture<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let result = ready!(this.inner.poll(cx));
        // We can ignore the error path here as the consumer is held for the lifetime of the healthcheck agent,
        // and a send error should signify that the Enclave is already unhealthy.
        log::warn!("{} exiting...", this.service);
        let _ = this.shutdown_channel.try_send(this.service.clone());
        std::task::Poll::Ready(result)
    }
}

#[cfg(test)]
mod test {
    use super::{NotifyShutdown, Service};
    use std::collections::BTreeSet;
    use tokio::sync::mpsc::channel;

    /// Every variant of [`Service`], in declaration order.
    ///
    /// Hand-maintained: plain Rust cannot derive a value list from an enum. The compile-time gate
    /// is [`expected_label`] below, whose wildcard-free `match` forces every new variant to be
    /// named and given a pinned string before the crate will build.
    const ALL_SERVICES: &[Service] = &[
        Service::DataPlane,
        Service::CryptoApi,
        Service::ClockSync,
        Service::DnsProxy,
        Service::EgressProxy,
        Service::E3Proxy,
        Service::ProvisionerProxy,
        Service::AcmeProxy,
        Service::ConfigServer,
        Service::EnvironmentLoader,
        Service::StatsClient,
        Service::TlsCerts,
        Service::TrustedCert,
        Service::EnvFinalize,
    ];

    /// The label each [`Service`] variant is contracted to render.
    ///
    /// This `match` is exhaustive with no wildcard arm, so a variant added to [`Service`] without
    /// a label here fails to *compile* rather than silently rendering an unchecked string. The
    /// [`std::fmt::Display`] impl is wildcard-free for the same reason; this is a second,
    /// independent gate on the same property, and additionally pins the exact strings.
    fn expected_label(service: &Service) -> &'static str {
        match service {
            Service::DataPlane => "data-plane",
            Service::CryptoApi => "crypto-api",
            Service::ClockSync => "clock-sync",
            Service::DnsProxy => "dns-proxy",
            Service::EgressProxy => "egress-proxy",
            Service::E3Proxy => "e3-proxy",
            Service::ProvisionerProxy => "provisioner-proxy",
            Service::AcmeProxy => "acme-proxy",
            Service::ConfigServer => "config-server",
            Service::EnvironmentLoader => "environment-loader",
            Service::StatsClient => "stats-client",
            Service::TlsCerts => "tls-certs",
            Service::TrustedCert => "trusted-cert",
            Service::EnvFinalize => "env-finalize",
        }
    }

    #[test]
    fn test_every_service_variant_has_a_distinct_non_empty_display_label() {
        let mut seen_labels = BTreeSet::new();
        for service in ALL_SERVICES {
            let label = service.to_string();
            assert!(
                !label.is_empty(),
                "{service:?} renders an empty Display label"
            );
            assert_eq!(
                label,
                expected_label(service),
                "{service:?} does not render its contracted Display label"
            );
            assert!(
                seen_labels.insert(label.clone()),
                "Display label {label:?} is used by more than one Service variant"
            );
        }
    }

    #[tokio::test]
    async fn test_notify_shutdown_service_exits_tasks_as_expected() {
        let (shutdown_channel, mut recv) = channel(1);
        let fut1 = async move { 1 }.notify_shutdown(Service::DataPlane, shutdown_channel);

        let result = fut1.await;
        assert_eq!(result, 1);
        // Assert that the task notified the shutdown channel on exit
        let msg = recv.try_recv();
        assert!(msg.is_ok());
        assert_eq!(msg.unwrap(), Service::DataPlane);
    }
}
