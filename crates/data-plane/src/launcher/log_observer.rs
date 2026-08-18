use crate::launcher::diagnostic::{Diagnostic, Severity};
use crate::launcher::observer::BootObserver;
use shared::notify_shutdown::Service;
use std::time::Duration;

/// Writes the boot sequence to the Enclave's log.
///
/// Every line is prefixed `[boot:<stage>]`, so one boot reads as a contiguous block and a single
/// stage can be picked out of an interleaved log:
///
/// ```text
/// [boot:load-environment] started
/// [boot:load-environment] env.malformed-variable-dropped — dropped malformed variable FOO
/// [boot:load-environment] completed in 412ms
/// ```
///
/// This is the only sink informational diagnostics reach, and the only one that sees them in the
/// order they were recorded relative to the stages around them.
pub struct LogObserver;

impl BootObserver for LogObserver {
    fn on_stage_start(&self, stage: &'static str) {
        log::info!("[boot:{stage}] started");
    }

    fn on_stage_complete(&self, stage: &'static str, elapsed: Duration) {
        log::info!("[boot:{stage}] completed in {}ms", elapsed.as_millis());
    }

    fn on_stage_failed(
        &self,
        stage: &'static str,
        blame: Service,
        error: &(dyn std::error::Error + 'static),
    ) {
        log::error!("[boot:{stage}] failed, blaming {blame} — {error}");
    }

    fn on_diagnostic(&self, stage: &'static str, diagnostic: &Diagnostic) {
        match diagnostic.severity() {
            Severity::Info => log::info!("[boot:{stage}] {diagnostic}"),
            Severity::Warning => log::warn!("[boot:{stage}] {diagnostic}"),
        }
    }
}
