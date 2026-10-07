use std::convert::Infallible;
use thiserror::Error;

/// The chain-level error: one variant per failure mode a stage can surface.
///
/// Each stage keeps its *own* [`Stage::Error`](crate::launcher::Stage::Error);
/// [`BootChain::then`](crate::launcher::BootChain::then) only requires
/// `BootError: From<S::Error>`, so a stage's error reaches the observer at its concrete type and is
/// widened afterwards. Nothing is flattened to `()`.
///
/// Follows the crate convention in [`crate::error`]: `#[from]` per source, em-dash separator, and
/// feature-gated variants where the source itself is feature-gated. None of the sources below are
/// feature-gated today.
#[derive(Debug, Error)]
pub enum BootError {
    #[error("Failed to initialize the Enclave environment — {0}")]
    Env(#[from] crate::env::EnvError),
    #[error("Failed to read the Enclave context — {0}")]
    Context(#[from] crate::ContextError),
    #[error("Boot stage failed on IO — {0}")]
    Io(#[from] std::io::Error),
}

/// A stage that cannot fail still has to satisfy `BootError: From<S::Error>`.
///
/// `Infallible` satisfies `Stage::Error`'s `std::error::Error + Send + Sync + 'static` bound, so a
/// stage which logs-and-continues (rather than aborting boot) declares `type Error = Infallible`
/// and needs this impl to compose. Landing it here means no later deliverable has to reach back and
/// edit this file.
impl From<Infallible> for BootError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}
