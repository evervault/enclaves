use shared::notify_shutdown::Service;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

/// A sink for boot-sequence events.
///
/// Implementors are expected to be cheap and non-blocking: the hooks are called inline on the boot
/// task, between stages. This is the one place in the boot abstraction that needs `dyn` — the chain
/// itself is statically composed, but the set of observers is a runtime decision.
pub trait BootObserver: Send + Sync + 'static {
    /// Called immediately before a stage is polled for the first time.
    fn on_stage_start(&self, stage: &'static str);
    /// Called once per stage that resolves to `Ok`.
    fn on_stage_complete(&self, stage: &'static str, elapsed: Duration);
    /// Called once per stage that resolves to `Err`. The chain halts after this.
    ///
    /// `blame` is the stage's [`Stage::BLAME`](crate::launcher::Stage::BLAME) — the critical
    /// service the healthcheck agent should name, instead of today's catch-all
    /// `Service::EnvironmentLoader`.
    fn on_stage_failed(
        &self,
        stage: &'static str,
        blame: Service,
        error: &(dyn std::error::Error + 'static),
    );
}

/// Fan-out to several observers, in registration order.
///
/// The boot sequence wants the same events delivered to logging, to the healthcheck agent and to
/// the shutdown notifier. Composing them here keeps [`BootContext`] holding a single `dyn`.
#[derive(Default)]
pub struct Observers(pub Vec<Box<dyn BootObserver>>);

impl Observers {
    pub fn new(observers: Vec<Box<dyn BootObserver>>) -> Self {
        Self(observers)
    }

    pub fn push(&mut self, observer: Box<dyn BootObserver>) {
        self.0.push(observer);
    }
}

impl BootObserver for Observers {
    fn on_stage_start(&self, stage: &'static str) {
        for observer in &self.0 {
            observer.on_stage_start(stage);
        }
    }

    fn on_stage_complete(&self, stage: &'static str, elapsed: Duration) {
        for observer in &self.0 {
            observer.on_stage_complete(stage, elapsed);
        }
    }

    fn on_stage_failed(
        &self,
        stage: &'static str,
        blame: Service,
        error: &(dyn std::error::Error + 'static),
    ) {
        for observer in &self.0 {
            observer.on_stage_failed(stage, blame.clone(), error);
        }
    }
}

/// Everything a stage needs that is not its own input.
///
/// `Clone` is load-bearing: [`BootChain::then`](crate::launcher::BootChain::then) clones one into
/// each stage's future. Carrying the shutdown notifier here is what lets a "spawn a daemon" stage
/// implement the same trait as a pure transform.
#[derive(Clone)]
pub struct BootContext {
    observer: Arc<dyn BootObserver>,
    shutdown_notifier: Sender<Service>,
}

impl BootContext {
    pub fn new(observer: Arc<dyn BootObserver>, shutdown_notifier: Sender<Service>) -> Self {
        Self {
            observer,
            shutdown_notifier,
        }
    }

    /// The channel the healthcheck agent watches for critical-service exits.
    ///
    /// Capacity is 1 by design — the first notification is terminal — so stages should treat a full
    /// channel as "already reported" rather than an error.
    pub fn shutdown_notifier(&self) -> &Sender<Service> {
        &self.shutdown_notifier
    }

    pub fn observer(&self) -> &dyn BootObserver {
        self.observer.as_ref()
    }

    pub fn on_stage_start(&self, stage: &'static str) {
        self.observer.on_stage_start(stage);
    }

    pub fn on_stage_complete(&self, stage: &'static str, elapsed: Duration) {
        self.observer.on_stage_complete(stage, elapsed);
    }

    pub fn on_stage_failed(
        &self,
        stage: &'static str,
        blame: Service,
        error: &(dyn std::error::Error + 'static),
    ) {
        self.observer.on_stage_failed(stage, blame, error);
    }
}
