use crate::launcher::observer::BootContext;
use shared::notify_shutdown::Service;
use std::future::Future;

/// One step of the Enclave's boot sequence.
///
/// Ordering is **structural**: a stage can only follow one whose `Out` is this stage's `In`. There
/// is no separate `NextPhase` marker to keep in sync — the chain *is* the ordering, and getting it
/// wrong is a type error rather than a runtime surprise.
///
/// The trait is deliberately **not object-safe** (`run` is generic in its return type, and `LABEL`
/// / `BLAME` are associated consts). The chain is statically composed; only the observer needs
/// `dyn`.
///
/// `run` returns `impl Future<Output = _> + Send` rather than a boxed future. The `+ Send` is not
/// decoration: the chain is driven from `start()`, which is `tokio::spawn`ed under
/// `Fut: Future + Send + 'static`. Building the runtime with `new_current_thread` does **not**
/// relax that bound — only a `LocalSet` would, and there is none in this repo. `async_trait` would
/// erase the bound behind a `Pin<Box<dyn Future>>`, so it is not used here.
///
/// # Ordering is enforced at compile time
///
/// A chain whose stages line up composes:
///
/// ```
/// use data_plane::launcher::stub::{LoadEnvironment, SeedInput, StartStatsClient};
/// use data_plane::launcher::{BootChain, BootContext, BootError};
///
/// // `StartStatsClient::Out` is `StatsClientStarted`, which is `LoadEnvironment::In`.
/// async fn in_order(ctx: BootContext, seed: SeedInput) -> Result<(), BootError> {
///     BootChain::seed(ctx, seed)
///         .then(StartStatsClient)
///         .then(LoadEnvironment)
///         .run()
///         .await?;
///     Ok(())
/// }
/// ```
///
/// Swapping two stages does not. The `E0271` on the fence below records the error this is meant to
/// produce, but note that stable rustdoc does **not** verify the code — only that the block fails
/// to compile at all. The observed error is quoted inside the block; if you change the chain and
/// this doctest starts passing for a different reason, that quote is what to check against.
///
/// ```compile_fail,E0271
/// use data_plane::launcher::stub::{LoadEnvironment, SeedInput, StartStatsClient};
/// use data_plane::launcher::{BootChain, BootContext, BootError};
///
/// // `LoadEnvironment::In` is `StatsClientStarted`, but the chain is still carrying `SeedInput`:
/// //
/// //   error[E0271]: type mismatch resolving `<LoadEnvironment as Stage>::In == SeedInput`
/// //     --> src/lib.rs:6:15
/// //      |
/// //    6 |         .then(LoadEnvironment)
/// //      |          ---- ^^^^^^^^^^^^^^^ expected `SeedInput`, found `StatsClientStarted`
/// async fn out_of_order(ctx: BootContext, seed: SeedInput) -> Result<(), BootError> {
///     BootChain::seed(ctx, seed)
///         .then(LoadEnvironment)
///         .then(StartStatsClient)
///         .run()
///         .await?;
///     Ok(())
/// }
/// ```
pub trait Stage: Send + 'static {
    /// What the previous stage produced.
    type In: Send;
    /// What this stage hands to the next one.
    type Out: Send;
    /// Each stage keeps its own failure mode. Nothing is flattened to `()`.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Stable identifier for logs, metrics and healthcheck reporting.
    const LABEL: &'static str;
    /// Which critical service the healthcheck agent should blame if this stage fails.
    const BLAME: Service;

    fn run(
        self,
        ctx: &BootContext,
        input: Self::In,
    ) -> impl Future<Output = Result<Self::Out, Self::Error>> + Send;
}
