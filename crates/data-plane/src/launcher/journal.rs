use crate::launcher::diagnostic::{Diagnostic, Severity};
use crate::launcher::observer::BootObserver;
use shared::notify_shutdown::Service;
use shared::server::health::{BootDiagnostic, BootReport};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// How many warnings a report will carry.
///
/// Bounding is not optional. [`BootContext`](crate::launcher::BootContext) is `Clone` and reaches
/// spawned daemons, so a clone can go on recording for the lifetime of the process long after its
/// stage finished. The cap makes that harmless rather than a slow leak into the healthcheck body.
const MAX_WARNINGS: usize = 32;

/// Accumulates what the boot sequence recorded, and hands it to the healthcheck server.
///
/// The journal is both the observer the chain writes into and the read handle the health server
/// reads out of — one shared object rather than a channel plus a store. Clones share the same
/// state, so registering a clone as an observer and keeping another to read from is the intended
/// use.
///
/// Only warnings are retained. Informational diagnostics reach the log observer and stop there:
/// nothing polls the healthcheck body for them, and keeping them would spend the cap on entries no
/// consumer reads.
#[derive(Clone, Default)]
pub struct BootJournal {
    state: Arc<Mutex<JournalState>>,
}

#[derive(Default)]
struct JournalState {
    stage: Option<&'static str>,
    warnings: Vec<BootDiagnostic>,
    dropped: u32,
}

impl BootJournal {
    /// The stage boot is in, or the stage it was in when it failed.
    pub fn stage(&self) -> Option<&'static str> {
        self.with_state(|state| state.stage)
    }

    /// Everything worth exporting, read under a single lock so that the stage, the warnings and the
    /// dropped count always describe the same moment.
    pub fn report(&self) -> BootReport {
        self.with_state(|state| BootReport {
            stage: state.stage.map(str::to_string),
            diagnostics: state.warnings.clone(),
            dropped: state.dropped,
        })
    }

    /// Recovers from poisoning rather than propagating it. The healthcheck path reads the journal
    /// on every request, and an observer hook that panicked mid-write leaves the state intact — a
    /// slightly stale report is a far better outcome there than a panicking healthcheck.
    fn with_state<R>(&self, read_or_write: impl FnOnce(&mut JournalState) -> R) -> R {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        read_or_write(&mut state)
    }
}

impl BootObserver for BootJournal {
    fn on_stage_start(&self, stage: &'static str) {
        self.with_state(|state| state.stage = Some(stage));
    }

    /// A chain is linear and runs once, so any completion means nothing is in flight — there is no
    /// outer stage for the field to fall back to.
    fn on_stage_complete(&self, _stage: &'static str, _elapsed: Duration) {
        self.with_state(|state| state.stage = None);
    }

    /// Deliberately empty: a failure **leaves the stage set**, so the report goes on naming the
    /// stage that broke for as long as the Enclave is up. The error itself is already carried to
    /// the healthcheck agent by the shutdown notifier, and to the log by the log observer.
    fn on_stage_failed(
        &self,
        _stage: &'static str,
        _blame: Service,
        _error: &(dyn std::error::Error + 'static),
    ) {
    }

    fn on_diagnostic(&self, stage: &'static str, diagnostic: &Diagnostic) {
        match diagnostic.severity() {
            Severity::Info => return,
            Severity::Warning => {}
        }

        self.with_state(|state| {
            // First N wins: the earliest warnings are the ones that explain how boot got into
            // whatever state produced the rest.
            if state.warnings.len() >= MAX_WARNINGS {
                state.dropped = state.dropped.saturating_add(1);
                return;
            }
            state.warnings.push(BootDiagnostic {
                stage: stage.to_string(),
                code: diagnostic.code().to_string(),
                message: diagnostic.message().to_string(),
            });
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn codes(report: &BootReport) -> Vec<&str> {
        report
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    #[test]
    fn the_in_flight_stage_is_cleared_once_it_completes() {
        let journal = BootJournal::default();
        assert_eq!(journal.stage(), None);

        journal.on_stage_start("alpha");
        assert_eq!(journal.stage(), Some("alpha"));

        journal.on_stage_complete("alpha", Duration::from_millis(1));
        assert_eq!(journal.stage(), None);
    }

    /// The report has to keep naming the stage that broke — that is the whole point of carrying the
    /// stage at all.
    #[test]
    fn a_failing_stage_stays_named() {
        let journal = BootJournal::default();

        journal.on_stage_start("bravo");
        journal.on_stage_failed(
            "bravo",
            Service::EnvironmentLoader,
            &std::io::Error::other("bravo broke"),
        );

        assert_eq!(journal.stage(), Some("bravo"));
        assert_eq!(journal.report().stage.as_deref(), Some("bravo"));
    }

    #[test]
    fn warnings_are_retained_and_informational_diagnostics_are_not() {
        let journal = BootJournal::default();

        journal.on_diagnostic("bravo", &Diagnostic::info("some.info", "nothing to see"));
        journal.on_diagnostic(
            "bravo",
            &Diagnostic::warn("some.warning", "something to see"),
        );

        let report = journal.report();
        assert_eq!(codes(&report), vec!["some.warning"]);
        assert_eq!(report.diagnostics[0].stage, "bravo");
        assert_eq!(report.diagnostics[0].message, "something to see");
    }

    #[test]
    fn an_empty_journal_produces_an_empty_report() {
        assert!(BootJournal::default().report().is_empty());
    }

    #[test]
    fn warnings_past_the_cap_are_counted_rather_than_kept() {
        let journal = BootJournal::default();
        let overflow = 8;

        for index in 0..MAX_WARNINGS + overflow {
            journal.on_diagnostic(
                "bravo",
                &Diagnostic::warn("some.warning", index.to_string()),
            );
        }

        let report = journal.report();
        assert_eq!(report.diagnostics.len(), MAX_WARNINGS);
        assert_eq!(report.dropped, overflow as u32);

        // First N wins, so the entries that survive are the earliest ones.
        assert_eq!(report.diagnostics.first().unwrap().message, "0");
        assert_eq!(
            report.diagnostics.last().unwrap().message,
            (MAX_WARNINGS - 1).to_string()
        );
    }

    /// The healthcheck server reads the journal on every request, so a panic that poisoned the lock
    /// must not turn every subsequent healthcheck into a panic too.
    #[test]
    fn a_poisoned_journal_still_reads() {
        let journal = BootJournal::default();
        journal.on_stage_start("alpha");
        journal.on_diagnostic("alpha", &Diagnostic::warn("some.warning", "recorded"));

        let panicked = catch_unwind(AssertUnwindSafe(|| {
            journal.with_state(|_| panic!("panicked while holding the journal lock"));
        }));
        assert!(panicked.is_err());

        let report = journal.report();
        assert_eq!(report.stage.as_deref(), Some("alpha"));
        assert_eq!(codes(&report), vec!["some.warning"]);
    }
}
