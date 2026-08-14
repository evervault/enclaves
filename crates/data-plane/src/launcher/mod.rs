//! Scaffolding for the Enclave's boot sequence.
//!
//! Boot runs **once**, left-to-right, with a different output type and a different failure mode at
//! each step. That is a forward-composed chain, not a stack of middleware — see `launcher.md` for
//! the argument against encoding it with `tower::Service`/`Layer`, which nests inside-out and so
//! forces every step to agree on one response type and one error type.
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
pub mod stub;

pub use chain::BootChain;
pub use error::BootError;
pub use observer::{BootContext, BootObserver, Observers};
pub use stage::Stage;
