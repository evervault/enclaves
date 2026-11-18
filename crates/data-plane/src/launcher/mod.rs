//! Scaffolding for the Enclave's boot sequence.
//!
//! Boot runs **once**, left-to-right, with a different output type and a different failure mode at
//! each step. This is distinct from the tower Layer structure, supporting our boot-time logic in
//! acting as a forward-composed chain of critical operations. This saves on the additional reverse
//! pass from the Layer abstraction.
//!
//! The in-repo idiom this follows is [`shared::notify_shutdown`]: a wrapper future that observes
//! another future's completion. [`BootChain`] applies the same trick to a *sequence*, wiring the
//! observation hooks exactly once in [`BootChain::then`] rather than re-implementing them per stage.
//!
//! Nothing here is on the boot path yet. [`stub`] carries throwaway fixtures whose only job is to
//! prove that the feature-gated chain shape typechecks in every CI feature combination.

pub mod chain;
pub mod error;
pub mod observer;
pub mod stage;

#[cfg(all(not(release), feature = "compiler_assertions"))]
pub mod stub;

pub use chain::BootChain;
pub use error::BootError;
pub use observer::{BootContext, BootObserver, Observers};
pub use stage::Stage;
