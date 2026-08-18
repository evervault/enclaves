use serde::{Deserialize, Serialize};

/// The body formats the Enclave's healthcheck can be served as.
///
/// The two sides of the bridge age at different rates. The control plane rolls forward on its own;
/// the data plane is baked into the Enclave image and only moves when that image is rebuilt, so the
/// Enclave is almost always the older of the two. Negotiation is what lets the newer control plane
/// ask for a format without assuming the Enclave can produce one: an Enclave predating a format
/// ignores the request and answers as it always has, and [`HealthCheckVersion::parse`] reads that
/// answer for what it is.
///
/// The Enclave answers in [`HealthCheckFormat::V1`] unless the caller names something newer. That
/// default covers the rarer reverse skew — a freshly built Enclave polled by a control plane that
/// has not rolled forward yet — where a body the caller cannot parse reads to the host as an
/// Enclave that cannot be reached at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthCheckFormat {
    /// [`DataPlaneState`] — the data plane's state, with everything it knows nested under
    /// `Initialized`.
    #[default]
    V1,
    /// [`DataPlaneHealth`] — the state and everything the data plane knows, side by side.
    V2,
}

impl HealthCheckFormat {
    /// Every format a caller can name, newest first. This is the preference order
    /// [`from_accept`](Self::from_accept) resolves in.
    const NEWEST_FIRST: [Self; 2] = [Self::V2, Self::V1];

    /// The `Content-Type` the Enclave answers with, and the token a caller puts in `Accept`.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::V1 => "application/json;version=1",
            Self::V2 => "application/json;version=2",
        }
    }

    /// The `Accept` header naming every format the caller understands, newest first.
    pub fn accept_header() -> String {
        Self::NEWEST_FIRST.map(Self::content_type).join(", ")
    }

    /// The newest format the caller named, falling back to the default when it named none this
    /// Enclave knows.
    ///
    /// Entries are matched whole rather than by substring: `version=20` contains `version=2`, and
    /// answering a caller in a format it never asked for is the one failure this must not have.
    pub fn from_accept(accept: Option<&str>) -> Self {
        let Some(accept) = accept else {
            return Self::default();
        };

        Self::NEWEST_FIRST
            .into_iter()
            .find(|format| {
                accept
                    .split(',')
                    .any(|entry| entry.trim() == format.content_type())
            })
            .unwrap_or_default()
    }

    /// The format a response body is in, read from its `Content-Type`. `None` for a body served
    /// before the header carried a version at all.
    pub fn from_content_type(content_type: Option<&str>) -> Option<Self> {
        let content_type = content_type?.trim();
        Self::NEWEST_FIRST
            .into_iter()
            .find(|format| format.content_type() == content_type)
    }
}

/// This is for representing healthcheck verions across the control-plane <-> data-plane http
/// boundary. It's not tied to v0/v1 enclaves release. There are many v1 enclaves that will
/// report v0 healthchecks until they are updated.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HealthCheckVersion {
    V0(HealthCheckLog),
    V1(DataPlaneState),
    V2(DataPlaneHealth),
}

impl HealthCheckVersion {
    pub fn status_code(&self) -> u16 {
        match self {
            HealthCheckVersion::V0(log) => log.status_code(),
            HealthCheckVersion::V1(dp_state) => dp_state.status_code(),
            HealthCheckVersion::V2(dp_health) => dp_health.status_code(),
        }
    }

    /// Read a healthcheck body in whichever format its `Content-Type` names.
    ///
    /// Keeping the mapping here means a new format costs one arm in this file, rather than an edit
    /// everywhere a healthcheck is read.
    pub fn parse(content_type: Option<&str>, body: &[u8]) -> serde_json::Result<Self> {
        Ok(match HealthCheckFormat::from_content_type(content_type) {
            Some(HealthCheckFormat::V2) => Self::V2(serde_json::from_slice(body)?),
            Some(HealthCheckFormat::V1) => Self::V1(serde_json::from_slice(body)?),
            None => Self::V0(serde_json::from_slice(body)?),
        })
    }
}

impl From<DataPlaneState> for HealthCheckVersion {
    fn from(state: DataPlaneState) -> Self {
        HealthCheckVersion::V1(state)
    }
}

impl From<DataPlaneHealth> for HealthCheckVersion {
    fn from(health: DataPlaneHealth) -> Self {
        HealthCheckVersion::V2(health)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCheckLog {
    pub status: HealthCheckStatus,
    pub message: Option<String>,
}

impl HealthCheckLog {
    pub fn new(status: HealthCheckStatus, message: Option<String>) -> HealthCheckLog {
        HealthCheckLog { status, message }
    }

    pub fn status_code(&self) -> u16 {
        self.status.status_code()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum HealthCheckStatus {
    Ignored,
    Ok,
    Unknown,
    Err,
    Uninitialized,
}

impl HealthCheckStatus {
    pub fn status_code(&self) -> u16 {
        match self {
            HealthCheckStatus::Ok | HealthCheckStatus::Ignored => 200,
            _ => 500,
        }
    }
}

impl std::fmt::Display for HealthCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use HealthCheckStatus::*;
        match self {
            Ignored => write!(f, "Ignored"),
            Ok => write!(f, "Ok"),
            Unknown => write!(f, "Unknown"),
            Err => write!(f, "Err"),
            Uninitialized => write!(f, "Uninitialized"),
        }
    }
}

pub trait HealthCheck {
    fn status_code(&self) -> u16;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlPlaneState {
    Draining,
    Ok,
    Error(String),
}

impl HealthCheck for ControlPlaneState {
    fn status_code(&self) -> u16 {
        match self {
            ControlPlaneState::Ok => 200,
            ControlPlaneState::Draining => 500,
            ControlPlaneState::Error(_) => 500,
        }
    }
}

impl HealthCheck for DataPlaneState {
    fn status_code(&self) -> u16 {
        if self.is_healthy() {
            200
        } else {
            500
        }
    }
}

impl HealthCheck for HealthCheckLog {
    fn status_code(&self) -> u16 {
        self.status_code()
    }
}

/// What the data plane's healthcheck reports, as [`HealthCheckFormat::V1`] serves it.
///
/// `Error` and `Unknown` are **control plane constructs**: the string they carry is the control
/// plane's own commentary on an Enclave it could not reach, or is deliberately not polling. The
/// data plane never produces either — it reports what it observed, and has no free-form slot to
/// write into.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataPlaneState {
    Error(String),
    Unknown(String),
    Provisioning,
    Attesting,
    SourcingTlsCerts,
    Initialized(DataPlaneDiagnostic),
}

impl DataPlaneState {
    /// Only an initialized data plane whose user process is answering is healthy. Every other state
    /// is the Enclave still on its way up, or a control plane reporting that it could not be
    /// reached.
    pub fn is_healthy(&self) -> bool {
        matches!(self, DataPlaneState::Initialized(diagnostic) if diagnostic.is_healthy())
    }
}

/// One thing the Enclave's boot sequence had to say about a stage beyond whether it succeeded.
///
/// Carries names, codes and counts only. Producers must never interpolate a value — an environment
/// variable's contents, a secret, key or certificate material — into `message`, because this
/// travels to the host and is recorded by the control plane.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BootDiagnostic {
    /// The boot stage that recorded it, stamped by the data plane rather than by the stage itself.
    pub stage: String,
    /// Stable and greppable, e.g. `"env.malformed-variable-dropped"`. This is what a consumer
    /// groups and alerts on; `message` is for a human reading one instance.
    pub code: String,
    pub message: String,
}

/// What the Enclave's boot sequence recorded, as exported in the healthcheck body.
///
/// A boot which succeeded with nothing to report leaves every field at its default, and each field
/// is skipped when empty — so a clean boot serializes to nothing at all and the enclosing body is
/// byte-identical to one produced with no boot reporting whatsoever. Consumers that do not know
/// about this field are unaffected; consumers that do can read a *successful but imperfect* boot for
/// as long as the Enclave is up, which no free-form status string survives.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct BootReport {
    /// The stage boot is in, or the stage it was in when it encountered issues.
    /// `None` when no stage is in flight, which covers both "boot finished" and
    /// "boot never started".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<BootDiagnostic>,
    /// Diagnostics discarded after the report hit the data plane's cap. Present so that a truncated
    /// report is never mistaken for a complete one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u32,
}

impl BootReport {
    /// Whether the report is worth serializing at all.
    pub fn is_empty(&self) -> bool {
        self.stage.is_none() && self.diagnostics.is_empty() && self.dropped == 0
    }
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataPlaneDiagnostic {
    pub user_process: UserProcessHealth,
}

impl DataPlaneDiagnostic {
    pub fn new(user_process: UserProcessHealth) -> Self {
        Self { user_process }
    }

    pub fn is_healthy(&self) -> bool {
        self.user_process.is_healthy()
    }
}

/// The data plane's state and the diagnostics its boot sequence recorded, side by side.
///
/// This is the shape [`HealthCheckFormat::V2`] serves, and it wraps the same [`DataPlaneState`] v1
/// reports rather than restating it — so the control plane's `Error` and `Unknown` messages, and
/// the reading v1 nests under `Initialized`, all arrive unchanged.
///
/// What v2 adds is `boot`. In v1 the only place for a diagnostic is inside `Initialized`, so a data
/// plane that failed or is still coming up has nowhere to say what it saw — exactly when an
/// operator most wants to know. Lifting it beside the state means every state can carry one.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataPlaneHealth {
    pub state: DataPlaneState,
    /// What the boot sequence recorded, in whatever state the data plane reached.
    #[serde(default, skip_serializing_if = "BootReport::is_empty")]
    pub boot: BootReport,
}

impl DataPlaneHealth {
    pub fn new(state: DataPlaneState) -> Self {
        Self {
            state,
            boot: BootReport::default(),
        }
    }

    pub fn with_boot(mut self, boot: BootReport) -> Self {
        self.boot = boot;
        self
    }

    /// Defers to the state. A boot report is context for an operator, not a verdict: it must never
    /// flip the Enclave's health or its healthcheck status code.
    pub fn is_healthy(&self) -> bool {
        self.state.is_healthy()
    }
}

impl HealthCheck for DataPlaneHealth {
    fn status_code(&self) -> u16 {
        self.state.status_code()
    }
}

/// Render a v2 body as the v1 body an Enclave or control plane predating v2 expects.
///
/// The state crosses untouched; the boot report is what v1 has nowhere to put. That single loss is
/// the whole reason v2 exists, and building v2 once and downgrading — rather than building each
/// version separately — is what keeps the two from disagreeing about anything else.
impl From<DataPlaneHealth> for DataPlaneState {
    fn from(health: DataPlaneHealth) -> Self {
        health.state
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UserProcessHealth {
    Unknown(String),
    Error(String),
    Response {
        status_code: u16,
        body: Option<serde_json::Value>,
    },
}

impl UserProcessHealth {
    /// Whether this reading should let the Enclave report itself healthy.
    ///
    /// `Unknown` does: it means nothing has been observed yet, which is not evidence of ill health.
    /// Both healthcheck body formats defer to this, so neither can drift from the other.
    pub fn is_healthy(&self) -> bool {
        match self {
            Self::Unknown(_) => true,
            Self::Error(_) => false,
            Self::Response { status_code, .. } => (200..300).contains(status_code),
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            UserProcessHealth::Unknown(_) => 0,
            UserProcessHealth::Error(_) => 2,
            UserProcessHealth::Response { status_code, .. } => {
                if *status_code >= 200 && *status_code < 300 {
                    1
                } else {
                    3
                }
            }
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

impl Ord for UserProcessHealth {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for UserProcessHealth {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn it_returns_errors_over_healthy_up_responses() {
        let max = [
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Response {
                status_code: 200,
                body: None,
            },
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(max, UserProcessHealth::Error(_)));
    }

    #[tokio::test]
    async fn it_returns_errors_over_unknown() {
        let max = [
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(max, UserProcessHealth::Error(_)));
    }

    #[tokio::test]
    async fn it_returns_unhealthy_up_responses_over_errors() {
        let max = [
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Unknown("".to_string()),
            UserProcessHealth::Error("".to_string()),
            UserProcessHealth::Response {
                status_code: 500,
                body: None,
            },
            UserProcessHealth::Unknown("".to_string()),
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(matches!(
            max,
            UserProcessHealth::Response {
                status_code: 500,
                body: None,
            }
        ));
    }

    fn user_process() -> UserProcessHealth {
        UserProcessHealth::Response {
            status_code: 200,
            body: None,
        }
    }

    fn initialized() -> DataPlaneState {
        DataPlaneState::Initialized(DataPlaneDiagnostic::new(user_process()))
    }

    fn populated_report() -> BootReport {
        BootReport {
            stage: Some("load-environment".to_string()),
            diagnostics: vec![BootDiagnostic {
                stage: "load-environment".to_string(),
                code: "env.malformed-variable-dropped".to_string(),
                message: "dropped 1 malformed environment variable".to_string(),
            }],
            dropped: 3,
        }
    }

    fn v2_health() -> DataPlaneHealth {
        DataPlaneHealth::new(initialized()).with_boot(populated_report())
    }

    // ---------------------------------------------------------------------------------------
    // Format negotiation. The Enclave must never answer in a format the caller did not name.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_caller_naming_no_format_gets_the_default() {
        assert_eq!(HealthCheckFormat::from_accept(None), HealthCheckFormat::V1);
        assert_eq!(
            HealthCheckFormat::from_accept(Some("text/plain")),
            HealthCheckFormat::V1
        );
        assert_eq!(
            HealthCheckFormat::from_accept(Some("")),
            HealthCheckFormat::V1
        );
    }

    #[test]
    fn a_caller_gets_the_newest_format_it_named() {
        assert_eq!(
            HealthCheckFormat::from_accept(Some("application/json;version=2")),
            HealthCheckFormat::V2
        );
        assert_eq!(
            HealthCheckFormat::from_accept(Some(&HealthCheckFormat::accept_header())),
            HealthCheckFormat::V2
        );
        assert_eq!(
            HealthCheckFormat::from_accept(Some("application/json;version=1")),
            HealthCheckFormat::V1
        );
    }

    /// Entries are matched whole. A substring match would read `version=20` as v2 and answer a
    /// caller in a format it cannot parse.
    #[test]
    fn a_format_this_enclave_does_not_know_is_not_mistaken_for_one_it_does() {
        assert_eq!(
            HealthCheckFormat::from_accept(Some("application/json;version=20")),
            HealthCheckFormat::V1
        );
    }

    #[test]
    fn a_response_is_read_in_the_format_its_content_type_names() {
        assert_eq!(HealthCheckFormat::from_content_type(None), None);
        assert_eq!(
            HealthCheckFormat::from_content_type(Some("application/json;version=1")),
            Some(HealthCheckFormat::V1)
        );
        assert_eq!(
            HealthCheckFormat::from_content_type(Some("application/json;version=2")),
            Some(HealthCheckFormat::V2)
        );
        // A body served before the header carried a version at all.
        assert_eq!(
            HealthCheckFormat::from_content_type(Some("application/json")),
            None
        );
    }

    // ---------------------------------------------------------------------------------------
    // Untagged discrimination. `HealthCheckVersion` picks the first variant that parses, so a
    // body read as the wrong version fails silently rather than loudly. Assert it directly.
    // ---------------------------------------------------------------------------------------

    fn parse_as_served(
        format: Option<HealthCheckFormat>,
        value: &impl Serialize,
    ) -> HealthCheckVersion {
        let body = serde_json::to_vec(value).unwrap();
        HealthCheckVersion::parse(format.map(HealthCheckFormat::content_type), &body).unwrap()
    }

    #[test]
    fn each_format_is_read_back_as_the_version_it_was_served_as() {
        let v0 = HealthCheckLog::new(HealthCheckStatus::Ok, Some("up".to_string()));

        assert!(matches!(
            parse_as_served(None, &v0),
            HealthCheckVersion::V0(_)
        ));
        assert!(matches!(
            parse_as_served(Some(HealthCheckFormat::V1), &initialized()),
            HealthCheckVersion::V1(_)
        ));
        assert!(matches!(
            parse_as_served(Some(HealthCheckFormat::V2), &v2_health()),
            HealthCheckVersion::V2(_)
        ));
    }

    /// The control plane nests a `HealthCheckVersion` in its own log and reads it back untagged,
    /// with no `Content-Type` to lean on. Every version has to survive that round trip as itself —
    /// and v2 wrapping the same `DataPlaneState` v1 reports is exactly where that could go wrong.
    #[test]
    fn every_version_survives_an_untagged_round_trip_as_itself() {
        let versions = [
            HealthCheckVersion::V0(HealthCheckLog::new(HealthCheckStatus::Ok, None)),
            HealthCheckVersion::V1(DataPlaneState::Provisioning),
            HealthCheckVersion::V1(initialized()),
            HealthCheckVersion::V2(v2_health()),
            HealthCheckVersion::V2(DataPlaneHealth::new(DataPlaneState::Provisioning)),
            HealthCheckVersion::V2(DataPlaneHealth::new(DataPlaneState::Error(
                "could not be reached".to_string(),
            ))),
        ];

        for version in versions {
            let encoded = serde_json::to_string(&version).unwrap();
            let decoded: HealthCheckVersion = serde_json::from_str(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(&version),
                std::mem::discriminant(&decoded),
                "{encoded} was read back as a different version"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // The verdict. v2 wraps the state rather than restating it, and must not reinterpret it.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn both_formats_return_the_same_status_code_for_the_same_state() {
        let states = [
            DataPlaneState::Unknown("draining".to_string()),
            DataPlaneState::Error("unreachable".to_string()),
            DataPlaneState::Provisioning,
            DataPlaneState::Attesting,
            DataPlaneState::SourcingTlsCerts,
            DataPlaneState::Initialized(DataPlaneDiagnostic::new(UserProcessHealth::Unknown(
                "nothing read yet".to_string(),
            ))),
            DataPlaneState::Initialized(DataPlaneDiagnostic::new(UserProcessHealth::Error(
                "the user process is gone".to_string(),
            ))),
            initialized(),
            DataPlaneState::Initialized(DataPlaneDiagnostic::new(UserProcessHealth::Response {
                status_code: 503,
                body: None,
            })),
        ];

        for state in states {
            for boot in [BootReport::default(), populated_report()] {
                let health = DataPlaneHealth::new(state.clone()).with_boot(boot);

                assert_eq!(
                    health.status_code(),
                    state.status_code(),
                    "v2 reinterpreted {state:?}"
                );
                assert_eq!(health.is_healthy(), state.is_healthy());
            }
        }
    }

    /// Only an initialized data plane answering healthily is healthy, and a boot report never
    /// changes that in either format.
    #[test]
    fn a_boot_report_is_never_a_verdict() {
        let healthy = DataPlaneHealth::new(initialized()).with_boot(populated_report());
        assert!(healthy.is_healthy());
        assert_eq!(healthy.status_code(), 200);

        let provisioning =
            DataPlaneHealth::new(DataPlaneState::Provisioning).with_boot(populated_report());
        assert!(!provisioning.is_healthy());
        assert_eq!(provisioning.status_code(), 500);
    }

    // ---------------------------------------------------------------------------------------
    // The v2 body itself.
    // ---------------------------------------------------------------------------------------

    /// The reason v2 exists: a data plane that never reached `Initialized` still reports what boot
    /// saw, where v1 has nowhere to put it.
    #[test]
    fn a_boot_report_survives_in_a_state_v1_cannot_carry_one_in() {
        let health =
            DataPlaneHealth::new(DataPlaneState::Provisioning).with_boot(populated_report());

        let encoded = serde_json::to_string(&health).unwrap();
        let decoded: DataPlaneHealth = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.boot, populated_report());

        // Downgrading to v1 is where it is lost, which is what v2 is for.
        assert!(matches!(
            DataPlaneState::from(health),
            DataPlaneState::Provisioning
        ));
    }

    #[test]
    fn a_v2_body_omits_a_boot_report_it_has_nothing_to_put_in() {
        assert_eq!(
            serde_json::to_string(&DataPlaneHealth::new(DataPlaneState::Provisioning)).unwrap(),
            r#"{"state":"Provisioning"}"#
        );
    }

    /// The state arrives exactly as v1 writes it, with the boot report beside it rather than buried
    /// inside it.
    #[test]
    fn a_v2_body_wraps_the_v1_state_and_puts_the_boot_report_beside_it() {
        assert_eq!(
            serde_json::to_string(&v2_health()).unwrap(),
            concat!(
                r#"{"state":{"Initialized":{"user_process":{"Response":{"status_code":200,"body":null}}}},"#,
                r#""boot":{"stage":"load-environment","#,
                r#""diagnostics":[{"stage":"load-environment","#,
                r#""code":"env.malformed-variable-dropped","#,
                r#""message":"dropped 1 malformed environment variable"}],"dropped":3}}"#
            )
        );
    }

    /// The control plane's own commentary rides in the state, so v2 needs no free-form slot of its
    /// own and the control plane never has to fall back to an older format to be heard.
    #[test]
    fn a_v2_body_carries_the_control_planes_message_in_the_state() {
        let health = DataPlaneHealth::new(DataPlaneState::Error(
            "Failed to contact data-plane for healthcheck".to_string(),
        ));

        assert_eq!(
            serde_json::to_string(&health).unwrap(),
            r#"{"state":{"Error":"Failed to contact data-plane for healthcheck"}}"#
        );
    }

    /// Downgrading is how the data plane answers a caller that predates v2. The state has to cross
    /// untouched; the boot report is the one thing v1 has no room for.
    #[test]
    fn downgrading_keeps_the_state_and_drops_only_the_boot_report() {
        let DataPlaneState::Initialized(diagnostic) = DataPlaneState::from(v2_health()) else {
            panic!("Expected an initialized data plane");
        };

        assert_eq!(diagnostic.user_process, user_process());
    }

    #[test]
    fn a_report_is_empty_only_while_every_field_is() {
        assert!(BootReport::default().is_empty());
        assert!(!populated_report().is_empty());
        assert!(!BootReport {
            dropped: 1,
            ..BootReport::default()
        }
        .is_empty());
    }
}
