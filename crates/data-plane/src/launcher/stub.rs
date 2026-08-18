//! Throwaway fixtures that pin down the *shape* of the boot chain before any real stage exists.
//!
//! None of this is on the boot path, and none of it does real work. Its entire job is to fail
//! `cargo check` if the feature-gated chain cannot be expressed — while the abstraction is still
//! free to change. The stage names and the order below mirror the real sequence so that the shape
//! being proved is the shape that will actually be built.
//!
//! These live outside `#[cfg(test)]` on purpose: `cargo check` does not build test code, and the
//! eight-combination `cargo check` matrix is the gate this module exists to satisfy.
//!
//! # The two traps this module exists to catch
//!
//! **`#[cfg]` cannot go on a method call mid-chain** — expression attributes are unstable — so the
//! chain has to be assembled with `#[cfg]`-gated `let` rebinding, which *is* stable.
//!
//! **The gated stages are not type-preserving.** `SourceTlsCerts` produces the intermediate CA
//! material that the cert resolver needs, and `SourceTrustedCert` adds the ACME trusted cert on top
//! of it, so the type the chain is carrying when it reaches the terminal stage genuinely differs
//! across feature combinations. Rebinding alone does not fix that: `FinalizeEnv::In` has to be
//! whatever the rebinding landed on. See [`boot`] for the resolution.

use crate::env::EnvError;
use crate::launcher::{BootChain, BootContext, BootError, Diagnostic, Stage};
use crate::ContextError;
use shared::notify_shutdown::Service;
use std::convert::Infallible;
use std::future::Future;

// ---------------------------------------------------------------------------------------------
// The values threaded through the chain. A distinct type per link is what makes ordering
// structural: there is exactly one order in which these compose.
// ---------------------------------------------------------------------------------------------

/// What the pre-chain in `main` already established, handed to the chain rather than re-derived.
#[derive(Debug)]
pub struct SeedInput {
    pub target_port: u16,
}

#[derive(Debug)]
pub struct StatsClientStarted {
    pub target_port: u16,
}

#[derive(Debug)]
pub struct EnvironmentLoaded {
    pub target_port: u16,
}

#[derive(Debug)]
pub struct ServicesSpawned {
    pub target_port: u16,
}

/// The last type that every feature combination agrees on — and therefore the name the gated tails
/// are written against.
#[derive(Debug)]
pub struct ListenerBound {
    pub target_port: u16,
}

/// Stands in for `(EnvironmentLoader<Finalize>, X509, PKey<Private>)`, today's out-of-band tuple.
#[cfg(feature = "tls_termination")]
#[derive(Debug)]
pub struct TlsCertsSourced {
    pub target_port: u16,
    pub intermediate_ca: String,
}

#[cfg(all(feature = "tls_termination", feature = "enclave"))]
#[derive(Debug)]
pub struct TrustedCertSourced {
    pub target_port: u16,
    pub intermediate_ca: String,
    pub trusted_cert: String,
}

/// What the chain yields. The caller — not the chain — then runs the server for the process
/// lifetime.
#[derive(Debug)]
pub struct ReadyToServe {
    pub target_port: u16,
}

// ---------------------------------------------------------------------------------------------
// The common prefix: present in every feature combination.
// ---------------------------------------------------------------------------------------------

/// `Error = Infallible` because registering the stats client logs and continues today, and must
/// keep doing so. This is the stage that makes `impl From<Infallible> for BootError` necessary.
pub struct StartStatsClient;

impl Stage for StartStatsClient {
    type In = SeedInput;
    type Out = StatsClientStarted;
    type Error = Infallible;

    const LABEL: &'static str = "start-stats-client";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(StatsClientStarted {
            target_port: input.target_port,
        })
    }
}

/// The one stage here that records diagnostics, so that the emit path is type-checked wherever the
/// chain itself is — including the feature combinations that build no test code.
pub struct LoadEnvironment;

impl Stage for LoadEnvironment {
    type In = StatsClientStarted;
    type Out = EnvironmentLoaded;
    type Error = EnvError;

    const LABEL: &'static str = "load-environment";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        ctx.record(Diagnostic::info(
            "stub.environment-not-loaded",
            "the stub environment loader read no variables",
        ));
        ctx.record(Diagnostic::warn(
            "stub.environment-not-validated",
            "the stub environment loader validated no variables",
        ));
        Ok(EnvironmentLoaded {
            target_port: input.target_port,
        })
    }
}

/// A stage that spawns daemons fits the same trait as a pure transform because the shutdown
/// notifier reaches it through [`BootContext`].
pub struct SpawnCriticalServices;

impl Stage for SpawnCriticalServices {
    type In = EnvironmentLoaded;
    type Out = ServicesSpawned;
    type Error = ContextError;

    const LABEL: &'static str = "spawn-critical-services";
    const BLAME: Service = Service::DataPlane;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(ServicesSpawned {
            target_port: input.target_port,
        })
    }
}

pub struct BindDataPlaneListener;

impl Stage for BindDataPlaneListener {
    type In = ServicesSpawned;
    type Out = ListenerBound;
    type Error = std::io::Error;

    const LABEL: &'static str = "bind-data-plane-listener";
    const BLAME: Service = Service::DataPlane;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(ListenerBound {
            target_port: input.target_port,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The feature-gated tail stages.
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "tls_termination")]
pub struct SourceTlsCerts;

#[cfg(feature = "tls_termination")]
impl Stage for SourceTlsCerts {
    type In = ListenerBound;
    type Out = TlsCertsSourced;
    type Error = EnvError;

    const LABEL: &'static str = "source-tls-certs";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(TlsCertsSourced {
            target_port: input.target_port,
            intermediate_ca: String::new(),
        })
    }
}

/// The ACME trusted cert is fetched inside the TLS path today, so this stage is gated on `enclave`
/// *within* `tls_termination` rather than on `enclave` alone.
#[cfg(all(feature = "tls_termination", feature = "enclave"))]
pub struct SourceTrustedCert;

#[cfg(all(feature = "tls_termination", feature = "enclave"))]
impl Stage for SourceTrustedCert {
    type In = TlsCertsSourced;
    type Out = TrustedCertSourced;
    type Error = std::io::Error;

    const LABEL: &'static str = "source-trusted-cert";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(TrustedCertSourced {
            target_port: input.target_port,
            intermediate_ca: input.intermediate_ca,
            trusted_cert: String::new(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The terminal stage — where Trap 2 is actually resolved.
//
// `FinalizeEnv` is one type with one `Out` and one `Error` in every build. What varies is its
// `In`, which is `#[cfg]`-selected to match whatever the gated rebinding in `boot` landed on.
// Nothing is made generic and nothing is erased: each of the three impls names a concrete type.
// ---------------------------------------------------------------------------------------------

/// Writes `EV_INITIALIZED`, unblocking the customer process. Deliberately last in every
/// combination: it must run after both the intermediate cert and the ACME trusted cert.
pub struct FinalizeEnv;

#[cfg(all(feature = "tls_termination", feature = "enclave"))]
impl Stage for FinalizeEnv {
    type In = TrustedCertSourced;
    type Out = ReadyToServe;
    type Error = EnvError;

    const LABEL: &'static str = "finalize-env";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(ReadyToServe {
            target_port: input.target_port,
        })
    }
}

#[cfg(all(feature = "tls_termination", not(feature = "enclave")))]
impl Stage for FinalizeEnv {
    type In = TlsCertsSourced;
    type Out = ReadyToServe;
    type Error = EnvError;

    const LABEL: &'static str = "finalize-env";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(ReadyToServe {
            target_port: input.target_port,
        })
    }
}

#[cfg(not(feature = "tls_termination"))]
impl Stage for FinalizeEnv {
    type In = ListenerBound;
    type Out = ReadyToServe;
    type Error = EnvError;

    const LABEL: &'static str = "finalize-env";
    const BLAME: Service = Service::EnvironmentLoader;

    async fn run(self, _ctx: &BootContext, input: Self::In) -> Result<Self::Out, Self::Error> {
        Ok(ReadyToServe {
            target_port: input.target_port,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Composition.
// ---------------------------------------------------------------------------------------------

/// The part of the boot sequence that is identical in every feature combination.
///
/// The return type names [`ListenerBound`] explicitly. That is the point: an `impl Future` whose
/// `Output` is anonymous would leave the gated tails below with nothing to be written against, and
/// the alternative — duplicating the whole prefix once per combination — is exactly the
/// `#[cfg]`-duplicated impl blocks in `env/mod.rs` that this design replaces.
///
/// Note the chain is returned rather than run: composition stays lazy, so the prefix and the tail
/// are still a single future.
pub fn common_prefix(
    ctx: BootContext,
    seed: SeedInput,
) -> BootChain<impl Future<Output = Result<ListenerBound, BootError>> + Send> {
    BootChain::seed(ctx, seed)
        .then(StartStatsClient)
        .then(LoadEnvironment)
        .then(SpawnCriticalServices)
        .then(BindDataPlaneListener)
}

/// The whole boot sequence, in every feature combination.
///
/// `#[cfg]` sits on `let` **statements** — statement attributes are stable, expression attributes
/// are not — so each gated stage either extends the chain or does not exist. The type the chain
/// carries after this block is therefore `TrustedCertSourced`, `TlsCertsSourced` or `ListenerBound`
/// depending on the build, and `FinalizeEnv` has a matching `#[cfg]`-selected `In` for each.
pub async fn boot(ctx: BootContext, seed: SeedInput) -> Result<ReadyToServe, BootError> {
    let chain = common_prefix(ctx, seed);
    #[cfg(feature = "tls_termination")]
    let chain = chain.then(SourceTlsCerts);
    #[cfg(all(feature = "tls_termination", feature = "enclave"))]
    let chain = chain.then(SourceTrustedCert);
    chain.then(FinalizeEnv).run().await
}

/// Asserts, at `cargo check` time in *every* feature combination, that the composed boot future
/// survives `tokio::spawn`'s `Fut: Future + Send + 'static` bound.
///
/// The equivalent test in `chain.rs` only runs in the four `not_enclave` combinations, so it cannot
/// cover the `enclave` tails. This is never called; it exists to be type-checked.
pub fn assert_boot_future_is_send(ctx: BootContext, seed: SeedInput) {
    fn requires_send<T: Send + 'static>(_: T) {}
    requires_send(boot(ctx, seed));
}
