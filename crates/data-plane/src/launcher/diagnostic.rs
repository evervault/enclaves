/// The longest message a diagnostic will carry. Messages are truncated at construction rather than
/// at export, so every sink sees the same text and no sink has to defend itself against a stage
/// that interpolated something enormous.
pub const MAX_MESSAGE_CHARS: usize = 256;

/// How far a diagnostic travels.
///
/// There is deliberately no `Error`. A stage that cannot continue returns `Err`, and
/// [`BootObserver::on_stage_failed`](crate::launcher::BootObserver::on_stage_failed) already
/// carries that error at its concrete type. A third severity would be a second route to the same
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Worth a log line, nothing more.
    Info,
    /// Boot continued, but not as intended. Exported in the healthcheck body.
    Warning,
}

/// Something a stage has to say about its own progress.
///
/// A diagnostic is **not an outcome**. The outcome is the stage's `Ok`/`Err`, which
/// [`BootChain`](crate::launcher::BootChain) already reports. A diagnostic carries what the outcome
/// cannot: work skipped, degraded, repaired or retried. Without it a stage that succeeds while
/// silently dropping something has nowhere to say so, and the Enclave boots looking perfectly
/// healthy.
///
/// A diagnostic never names the stage that recorded it. The stage is stamped on by
/// [`BootContext`](crate::launcher::BootContext), so a stage cannot misattribute its own output.
///
/// # NEVER PUT A VALUE IN A MESSAGE
///
/// Messages are serialized into the healthcheck body, which the host polls and the control plane
/// records. **CARRY NAMES, CODES AND COUNTS. NEVER VALUES** — no environment variable contents, no
/// decrypted secrets, no key or certificate material, no request bodies. Nothing in the type
/// enforces this; review does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    severity: Severity,
    code: &'static str,
    message: String,
}

impl Diagnostic {
    /// Record something worth a log line and nothing more.
    pub fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    /// Record that boot continued, but not as intended.
    pub fn warn(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    /// `code` is `&'static str` on purpose: it is the field consumers group and alert on, so it has
    /// to be a literal in the source — stable, greppable, and impossible to interpolate a value
    /// into.
    fn new(severity: Severity, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity,
            code,
            message: truncate_to_max_chars(message.into()),
        }
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The form diagnostics take in the log, and the reason sinks do not each invent their own.
impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} — {}", self.code, self.message)
    }
}

/// Truncate on a character boundary. `String::truncate` panics mid-codepoint, and a message built
/// from a variable name is not guaranteed to be ASCII.
fn truncate_to_max_chars(mut message: String) -> String {
    if let Some((byte_index, _)) = message.char_indices().nth(MAX_MESSAGE_CHARS) {
        message.truncate(byte_index);
    }
    message
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn severity_is_carried_through_construction() {
        assert_eq!(
            Diagnostic::info("some.code", "message").severity(),
            Severity::Info
        );
        assert_eq!(
            Diagnostic::warn("some.code", "message").severity(),
            Severity::Warning
        );
    }

    #[test]
    fn a_message_within_the_limit_is_untouched() {
        let message = "x".repeat(MAX_MESSAGE_CHARS);
        let diagnostic = Diagnostic::warn("some.code", message.clone());
        assert_eq!(diagnostic.message(), message);
    }

    #[test]
    fn a_longer_message_is_truncated_to_the_limit() {
        let diagnostic = Diagnostic::warn("some.code", "x".repeat(MAX_MESSAGE_CHARS + 100));
        assert_eq!(diagnostic.message().chars().count(), MAX_MESSAGE_CHARS);
    }

    /// A message built from a variable name is not guaranteed to be ASCII, so the cut has to land
    /// on a character boundary rather than a byte offset.
    #[test]
    fn a_multi_byte_message_is_truncated_on_a_character_boundary() {
        let diagnostic = Diagnostic::warn("some.code", "é".repeat(MAX_MESSAGE_CHARS + 100));
        assert_eq!(diagnostic.message().chars().count(), MAX_MESSAGE_CHARS);
        assert!(diagnostic.message().chars().all(|c| c == 'é'));
    }

    #[test]
    fn display_pairs_the_code_with_the_message() {
        let diagnostic = Diagnostic::warn("env.malformed-variable-dropped", "dropped FOO");
        assert_eq!(
            diagnostic.to_string(),
            "env.malformed-variable-dropped — dropped FOO"
        );
    }
}
