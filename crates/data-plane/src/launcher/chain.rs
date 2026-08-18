use crate::launcher::error::BootError;
use crate::launcher::observer::BootContext;
use crate::launcher::stage::Stage;
use std::future::Future;
use std::time::Instant;

/// A boot sequence under construction.
///
/// `BootChain` is a *forward* composition: each [`then`](Self::then) wraps the accumulated future
/// in a slightly larger one, so the chain reads in execution order and each link keeps its own
/// output type. Contrast a `tower::Layer` stack, which nests inside-out and therefore forces the
/// innermost service's `Response` and `Error` onto everything above it.
///
/// `F` is the accumulated future. It is always an opaque `impl Future`, never a
/// `Pin<Box<dyn Future>>` — boxing would erase the `Send` bound that `tokio::spawn` needs.
pub struct BootChain<F> {
    ctx: BootContext,
    fut: F,
}

impl<T: Send> BootChain<std::future::Ready<Result<T, BootError>>> {
    /// Seed the chain with whatever the pre-chain in `main` already established, so nothing is
    /// re-derived.
    ///
    /// The first two boot steps (parse argv, load `FeatureContext`) are genuinely pre-chain: the
    /// observers cannot exist before the healthcheck agent does, and the agent cannot be built
    /// before the config is read. Their results are handed in here instead.
    pub fn seed(ctx: BootContext, input: T) -> Self {
        Self {
            ctx,
            fut: std::future::ready(Ok(input)),
        }
    }
}

impl<F, T> BootChain<F>
where
    F: Future<Output = Result<T, BootError>> + Send,
    T: Send,
{
    /// Append a stage.
    ///
    /// `S: Stage<In = T>` is the whole ordering guarantee: this will not compile unless `stage`
    /// consumes exactly what the chain is currently carrying.
    ///
    /// The observation hooks are wired **here, once** — no stage re-implements them, and no stage
    /// can forget to. Note there is deliberately no retry around `stage.run`: stages are not
    /// uniformly idempotent (spawning daemons and finalizing the environment are not), so retry
    /// belongs inside the stages that want it.
    pub fn then<S>(
        self,
        stage: S,
    ) -> BootChain<impl Future<Output = Result<S::Out, BootError>> + Send>
    where
        S: Stage<In = T>,
        BootError: From<S::Error>,
    {
        let Self { ctx, fut: prev } = self;
        // The stage is stamped onto the clone the stage runs with, so anything it records is
        // attributed here rather than by the stage itself.
        let observed = ctx.clone().for_stage(S::LABEL);
        let fut = async move {
            // A failure upstream short-circuits here, so later stages never run and never report.
            let input = prev.await?;
            observed.on_stage_start(S::LABEL);
            let started = Instant::now();
            match stage.run(&observed, input).await {
                Ok(out) => {
                    observed.on_stage_complete(S::LABEL, started.elapsed());
                    Ok(out)
                }
                Err(e) => {
                    // The observer sees the stage's own concrete error type; widening to
                    // `BootError` happens only afterwards.
                    observed.on_stage_failed(S::LABEL, S::BLAME, &e);
                    Err(BootError::from(e))
                }
            }
        };
        BootChain { ctx, fut }
    }

    /// Drive the composed sequence, yielding whatever the last stage produced.
    ///
    /// The chain's job is to produce a *ready-to-serve* value; the caller runs the server. A
    /// never-completing accept loop must not be a stage, or `on_stage_complete` would never fire
    /// and the boot would look permanently in flight.
    pub async fn run(self) -> Result<T, BootError> {
        self.fut.await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::env::EnvError;
    use crate::launcher::diagnostic::Diagnostic;
    use crate::launcher::journal::BootJournal;
    use crate::launcher::log_observer::LogObserver;
    use crate::launcher::observer::{BootObserver, Observers, PRE_CHAIN_STAGE};
    use shared::notify_shutdown::Service;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Start(&'static str),
        Complete(&'static str),
        Failed(&'static str, Service, String),
        /// The stage the chain attributed the diagnostic to, and the diagnostic's code.
        Diagnostic(&'static str, &'static str),
    }

    /// Records every hook onto one timeline, which is what makes the *ordering* of diagnostics
    /// relative to start, complete and failure assertable. Clones share that timeline, so the same
    /// recorder can be registered inside an [`Observers`] fan-out and still read from afterwards.
    #[derive(Clone, Default)]
    struct Recorder {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl Recorder {
        fn record(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }

        fn labels_started(&self) -> Vec<&'static str> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|event| match event {
                    Event::Start(label) => Some(*label),
                    _ => None,
                })
                .collect()
        }
    }

    impl BootObserver for Recorder {
        fn on_stage_start(&self, stage: &'static str) {
            self.record(Event::Start(stage));
        }

        fn on_stage_complete(&self, stage: &'static str, _elapsed: Duration) {
            self.record(Event::Complete(stage));
        }

        fn on_stage_failed(
            &self,
            stage: &'static str,
            blame: Service,
            error: &(dyn std::error::Error + 'static),
        ) {
            self.record(Event::Failed(stage, blame, error.to_string()));
        }

        fn on_diagnostic(&self, stage: &'static str, diagnostic: &crate::launcher::Diagnostic) {
            self.record(Event::Diagnostic(stage, diagnostic.code()));
        }
    }

    /// Each test stage takes a different `In` and produces a different `Out`, so the chain below
    /// only composes in one order.
    struct Alpha;

    impl Stage for Alpha {
        type In = u8;
        type Out = u16;
        type Error = std::io::Error;

        const LABEL: &'static str = "alpha";
        const BLAME: Service = Service::ConfigServer;

        async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
            Ok(u16::from(input) + 1)
        }
    }

    struct Bravo {
        fail: bool,
    }

    impl Stage for Bravo {
        type In = u16;
        type Out = u32;
        type Error = EnvError;

        const LABEL: &'static str = "bravo";
        const BLAME: Service = Service::EnvironmentLoader;

        async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
            if self.fail {
                Err(EnvError::Crypto("bravo could not decrypt".to_string()))
            } else {
                Ok(u32::from(input) + 1)
            }
        }
    }

    /// `Error = Infallible` exercises `impl From<Infallible> for BootError` in a real composition.
    struct Charlie {
        ran: Arc<AtomicBool>,
    }

    impl Stage for Charlie {
        type In = u32;
        type Out = String;
        type Error = Infallible;

        const LABEL: &'static str = "charlie";
        const BLAME: Service = Service::DataPlane;

        async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
            self.ran.store(true, Ordering::SeqCst);
            Ok(input.to_string())
        }
    }

    /// Records as it runs, so the diagnostic channel is exercised through a real composition rather
    /// than by calling the observer directly. Shares `Bravo`'s input and output types, so it drops
    /// into the same position in a chain.
    struct Echo {
        diagnostics: Vec<Diagnostic>,
        fail: bool,
    }

    impl Stage for Echo {
        type In = u16;
        type Out = u32;
        type Error = EnvError;

        const LABEL: &'static str = "echo";
        const BLAME: Service = Service::EnvironmentLoader;

        async fn run(self, ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
            // Nothing here names "echo". Attribution comes from the chain, which is the property
            // the tests below check.
            for diagnostic in self.diagnostics {
                ctx.record(diagnostic);
            }

            if self.fail {
                Err(EnvError::Crypto("echo could not decrypt".to_string()))
            } else {
                Ok(u32::from(input) + 1)
            }
        }
    }

    /// Hands its context back to the test so a diagnostic can be recorded from a clone *after* the
    /// stage has completed — the situation a stage which spawns a long-lived daemon creates.
    struct Foxtrot {
        captured: Arc<Mutex<Option<BootContext>>>,
    }

    impl Stage for Foxtrot {
        type In = u32;
        type Out = String;
        type Error = Infallible;

        const LABEL: &'static str = "foxtrot";
        const BLAME: Service = Service::DataPlane;

        async fn run(self, ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
            *self.captured.lock().unwrap() = Some(ctx.clone());
            Ok(input.to_string())
        }
    }

    fn context() -> (Recorder, BootContext, Receiver<Service>) {
        let recorder = Recorder::default();
        let (notifier, receiver): (Sender<Service>, Receiver<Service>) = channel(1);
        let ctx = BootContext::new(Arc::new(recorder.clone()), notifier);
        (recorder, ctx, receiver)
    }

    /// A context whose observer is the real fan-out, carrying the sinks the Enclave registers.
    ///
    /// `on_diagnostic` is defaulted, so an `Observers` which failed to forward it would leave every
    /// test built on `context()` passing while the channel was inert in production. At least one
    /// test has to go through here.
    fn fanned_out_context() -> (Recorder, BootJournal, BootContext, Receiver<Service>) {
        let recorder = Recorder::default();
        let journal = BootJournal::default();
        let observers = Observers::new(vec![
            Box::new(LogObserver),
            Box::new(journal.clone()),
            Box::new(recorder.clone()),
        ]);
        let (notifier, receiver): (Sender<Service>, Receiver<Service>) = channel(1);
        let ctx = BootContext::new(Arc::new(observers), notifier);
        (recorder, journal, ctx, receiver)
    }

    fn recording_echo(fail: bool) -> Echo {
        Echo {
            diagnostics: vec![
                Diagnostic::info("echo.informational", "worth a log line"),
                Diagnostic::warn("echo.degraded", "continued, but not as intended"),
            ],
            fail,
        }
    }

    #[tokio::test]
    async fn emits_start_and_complete_once_per_stage_in_chain_order() {
        let (recorder, ctx, _receiver) = context();
        let ran = Arc::new(AtomicBool::new(false));

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(Bravo { fail: false })
            .then(Charlie { ran: ran.clone() })
            .run()
            .await;

        assert_eq!(result.unwrap(), "3");
        assert!(ran.load(Ordering::SeqCst));
        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![
                Event::Start("alpha"),
                Event::Complete("alpha"),
                Event::Start("bravo"),
                Event::Complete("bravo"),
                Event::Start("charlie"),
                Event::Complete("charlie"),
            ]
        );
    }

    #[tokio::test]
    async fn failing_stage_is_blamed_and_the_chain_halts() {
        let (recorder, ctx, _receiver) = context();
        let ran = Arc::new(AtomicBool::new(false));

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(Bravo { fail: true })
            .then(Charlie { ran: ran.clone() })
            .run()
            .await;

        let err = result.expect_err("the chain should surface bravo's failure");
        assert!(matches!(err, BootError::Env(_)));

        // The failure is attributed to the stage that produced it, not to a catch-all.
        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![
                Event::Start("alpha"),
                Event::Complete("alpha"),
                Event::Start("bravo"),
                Event::Failed(
                    "bravo",
                    Service::EnvironmentLoader,
                    "bravo could not decrypt".to_string()
                ),
            ]
        );

        // The chain halts: charlie is neither observed nor run.
        assert_eq!(recorder.labels_started(), vec!["alpha", "bravo"]);
        assert!(!ran.load(Ordering::SeqCst));
    }

    /// A succeeding stage still gets to say something, and what it says is attributed to it without
    /// it ever naming itself.
    #[tokio::test]
    async fn diagnostics_are_attributed_to_the_recording_stage_and_ordered_within_it() {
        let (recorder, ctx, _receiver) = context();

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(recording_echo(false))
            .run()
            .await;

        assert_eq!(result.unwrap(), 3);
        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![
                Event::Start("alpha"),
                Event::Complete("alpha"),
                Event::Start("echo"),
                Event::Diagnostic("echo", "echo.informational"),
                Event::Diagnostic("echo", "echo.degraded"),
                Event::Complete("echo"),
            ]
        );
    }

    /// Diagnostics recorded on the way to a failure have to reach the observer *before* the failure
    /// does, or a reader cannot tell which of them described the run-up to it.
    #[tokio::test]
    async fn diagnostics_recorded_before_a_failure_land_ahead_of_it() {
        let (recorder, ctx, _receiver) = context();
        let ran = Arc::new(AtomicBool::new(false));

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(recording_echo(true))
            .then(Charlie { ran: ran.clone() })
            .run()
            .await;

        assert!(matches!(
            result.expect_err("the chain should surface echo's failure"),
            BootError::Env(_)
        ));
        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![
                Event::Start("alpha"),
                Event::Complete("alpha"),
                Event::Start("echo"),
                Event::Diagnostic("echo", "echo.informational"),
                Event::Diagnostic("echo", "echo.degraded"),
                Event::Failed(
                    "echo",
                    Service::EnvironmentLoader,
                    "echo could not decrypt".to_string()
                ),
            ]
        );
        assert!(!ran.load(Ordering::SeqCst));
    }

    /// Anything recorded outside a stage is attributed to the pre-chain, rather than to whichever
    /// stage happened to run last.
    #[tokio::test]
    async fn a_context_that_has_not_entered_a_stage_records_against_the_pre_chain() {
        let (recorder, ctx, _receiver) = context();

        ctx.record(Diagnostic::warn(
            "pre.degraded",
            "recorded before the chain started",
        ));

        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![Event::Diagnostic(PRE_CHAIN_STAGE, "pre.degraded")]
        );
    }

    /// A context that outlives its stage keeps that stage's attribution instead of drifting onto a
    /// later one. This is the accepted cost of `BootContext` being `Clone`, and it is pinned here
    /// rather than left to be rediscovered.
    #[tokio::test]
    async fn a_context_clone_keeps_its_stage_after_that_stage_completes() {
        let (recorder, ctx, _receiver) = context();
        let captured = Arc::new(Mutex::new(None));

        BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(Bravo { fail: false })
            .then(Foxtrot {
                captured: captured.clone(),
            })
            .run()
            .await
            .expect("the chain should succeed");

        let escaped = captured
            .lock()
            .unwrap()
            .take()
            .expect("foxtrot should have captured its context");
        escaped.record(Diagnostic::warn(
            "foxtrot.late",
            "recorded after the stage completed",
        ));

        assert_eq!(
            recorder.events.lock().unwrap().last(),
            Some(&Event::Diagnostic("foxtrot", "foxtrot.late"))
        );
    }

    #[tokio::test]
    async fn the_observer_fan_out_delivers_diagnostics_to_every_sink() {
        let (recorder, journal, ctx, _receiver) = fanned_out_context();

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(recording_echo(false))
            .run()
            .await;

        assert_eq!(result.unwrap(), 3);

        // Every sink is reached, in registration order and in the order the stage recorded.
        assert_eq!(
            *recorder.events.lock().unwrap(),
            vec![
                Event::Start("alpha"),
                Event::Complete("alpha"),
                Event::Start("echo"),
                Event::Diagnostic("echo", "echo.informational"),
                Event::Diagnostic("echo", "echo.degraded"),
                Event::Complete("echo"),
            ]
        );

        // The journal keeps the warning for export, drops the informational one, and reports no
        // stage in flight now that the chain has finished.
        let report = journal.report();
        assert_eq!(report.stage, None);
        assert_eq!(report.dropped, 0);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].stage, "echo");
        assert_eq!(report.diagnostics[0].code, "echo.degraded");
        assert_eq!(
            report.diagnostics[0].message,
            "continued, but not as intended"
        );
    }

    /// A failed boot goes on naming the stage that broke, so an operator reading the report long
    /// after the fact still knows where it stopped.
    #[tokio::test]
    async fn the_journal_keeps_naming_the_stage_that_failed() {
        let (_recorder, journal, ctx, _receiver) = fanned_out_context();

        let result = BootChain::seed(ctx, 1u8)
            .then(Alpha)
            .then(recording_echo(true))
            .run()
            .await;

        assert!(result.is_err());

        let report = journal.report();
        assert_eq!(report.stage.as_deref(), Some("echo"));
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code, "echo.degraded");
    }

    #[test]
    fn composed_future_is_send() {
        fn requires_send<T: Send>(_: T) {}

        let (_recorder, ctx, _receiver) = context();
        let ran = Arc::new(AtomicBool::new(false));

        // `run()` is `tokio::spawn`ed under `Fut: Future + Send + 'static`, so the whole
        // composition has to survive that bound.
        requires_send(
            BootChain::seed(ctx.clone(), 1u8)
                .then(Alpha)
                .then(Bravo { fail: false })
                .then(Charlie { ran })
                .run(),
        );

        // Recording must not cost the composition its `Send`.
        requires_send(
            BootChain::seed(ctx, 1u8)
                .then(Alpha)
                .then(recording_echo(false))
                .run(),
        );
    }

    #[cfg(feature = "compiler_assertions")]
    #[test]
    fn stub_boot_future_is_send() {
        fn requires_send<T: Send>(_: T) {}

        let (_recorder, ctx, _receiver) = context();
        requires_send(crate::launcher::stub::boot(
            ctx,
            crate::launcher::stub::SeedInput { target_port: 8008 },
        ));
    }
}
