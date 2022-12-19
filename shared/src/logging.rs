use chrono::SecondsFormat;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, time::SystemTime};

use hyper::{
    header::{self, CONTENT_TYPE, USER_AGENT},
    http::HeaderValue,
    Body, HeaderMap, Request, Response,
};

use rand::{thread_rng, Rng};

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
#[serde(rename_all = "camelCase")]
pub struct TrxContext {
    txid: String,
    ts: String,
    msg: String,
    uri: String,
    r#type: String,
    request_method: String,
    #[builder(default)]
    request_headers: Option<String>,
    #[builder(default)]
    user_agent: Option<String>,
    #[builder(default)]
    response_headers: Option<String>,
    #[builder(default)]
    response_code: Option<String>,
    cage_name: String,
    cage_uuid: String,
    app_uuid: String,
    team_uuid: String,
    #[builder(default)]
    n_decrypted_fields: Option<u32>,
    #[builder(default)]
    content_type: Option<String>,
    #[builder(default)]
    response_content_type: Option<String>,
    #[builder(default)]
    elapsed: Option<f64>,
}

impl TrxContext {
    pub fn record_trx(mut self) {
        if self.response_code.is_none() {
            self.response_code = Some("ERR".to_string());
        }
        let json_log = serde_json::to_string(&self);

        if let Ok(log) = json_log {
            println!("{}", log);
        }
    }
}

#[derive(Clone)]
pub struct TrxContextId {
    txid: u128,
}

impl TrxContextId {
    pub fn new() -> Self {
        Self {
            txid: thread_rng().gen::<u128>(),
        }
    }
}

impl Default for TrxContextId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TrxContextId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}", self.txid)
    }
}

impl TrxContextBuilder {
    fn new() -> TrxContextBuilder {
        let timestamp = get_iso_timestamp();
        let trx_id = format!("{}", TrxContextId::new());
        let trx_type = "cage_trx".to_string();
        TrxContextBuilder {
            txid: Some(trx_id),
            ts: Some(timestamp),
            msg: Some("Cage Transaction Complete".to_string()),
            uri: None,
            r#type: Some(trx_type),
            request_method: None,
            request_headers: None,
            user_agent: None,
            response_headers: None,
            response_code: None,
            cage_name: None,
            cage_uuid: None,
            team_uuid: None,
            app_uuid: None,
            n_decrypted_fields: None,
            content_type: None,
            response_content_type: None,
            elapsed: None,
        }
    }

    pub fn get_timer() -> SystemTime {
        std::time::SystemTime::now()
    }

    pub fn stop_timer_and_build(
        &mut self,
        started: SystemTime,
    ) -> Result<TrxContext, TrxContextBuilderError> {
        let elapsed = started.elapsed().unwrap().as_millis() as f64;
        self.elapsed(Some(elapsed));
        self.build()
    }

    pub fn init_trx_context_with_cage_details(
        cage_uuid: &str,
        cage_name: &str,
        app_uuid: &str,
        team_uuid: &str,
    ) -> Self {
        let mut trx_context = Self::new();
        trx_context.cage_uuid(cage_uuid.to_string());
        trx_context.cage_name(cage_name.to_string());
        trx_context.app_uuid(app_uuid.to_string());
        trx_context.team_uuid(team_uuid.to_string());
        trx_context
    }

    pub fn get_trx_id(&self) -> String {
        self.txid
            .clone()
            .unwrap_or_else(|| format!("{:X}", thread_rng().gen::<u128>()))
    }

    pub fn add_req_to_trx_context(&mut self, req: &Request<Body>) {
        self.uri(req.uri().to_string());
        self.request_method(req.method().to_string());
        self.add_headers_to_request(req.headers());

        //Pull out content type
        if let Some(content_type) = req.headers().get(CONTENT_TYPE) {
            let content_type_str = content_type
                .to_str()
                .expect("Infallible - Failed to convert HeaderValue of ContentType to String");
            self.content_type(Some(content_type_str.to_string()));
        }

        //Pull out user agent
        if let Some(user_agent) = req.headers().get(USER_AGENT) {
            let user_agent_str = user_agent
                .to_str()
                .expect("Infallible - Failed to convert HeaderValue of ContentType to String");
            self.user_agent(Some(user_agent_str.into()));
        }
    }

    pub fn add_res_to_trx_context(&mut self, res: &Response<Body>) {
        self.response_code(Some(res.status().as_u16().to_string()));
        self.add_headers_to_response(res.headers());

        //Pull out content type
        if let Some(content_type) = res.headers().get(CONTENT_TYPE) {
            let content_type_str = content_type
                .to_str()
                .expect("Infallible - Failed to convert HeaderValue of ContentType to String");
            self.response_content_type(Some(content_type_str.into()));
        }
    }

    fn add_headers_to_request(&mut self, headers: &HeaderMap<HeaderValue>) {
        let headers_map = convert_headers_to_map(headers);
        if let Ok(headers_string) = serde_json::to_string(&headers_map) {
            self.request_headers(Some(headers_string));
        }
    }

    fn add_headers_to_response(&mut self, headers: &HeaderMap<HeaderValue>) {
        let headers_map = convert_headers_to_map(headers);
        if let Ok(headers_string) = serde_json::to_string(&headers_map) {
            self.response_headers(Some(headers_string));
        }
    }

    pub fn can_build(&mut self) -> bool {
        self.uri.is_some()
            & self.cage_name.is_some()
            & self.cage_uuid.is_some()
            & self.request_method.is_some()
            & self.request_headers.is_some()
    }
}

fn get_iso_timestamp() -> String {
    let timestamp: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn convert_headers_to_map(headers: &HeaderMap<HeaderValue>) -> Map<String, Value> {
    let mut tracked_headers: Map<String, Value> = Map::new();
    for (header_key, header_value) in headers {
        match header_value.to_str() {
            Ok(header_value_str) if NON_SENSITIVE_HEADERS.contains(&header_key.to_string()) => {
                tracked_headers.insert(
                    header_key.to_string(),
                    Value::String(header_value_str.to_string()),
                );
            }
            _ => {
                tracked_headers.insert(header_key.to_string(), Value::String("***".to_string()));
            }
        }
    }
    tracked_headers
}

lazy_static::lazy_static!(
    pub static ref NON_SENSITIVE_HEADERS: HashSet<String> = create_non_sensitive_header_set();
);

fn create_non_sensitive_header_set() -> HashSet<String> {
    let mut header_set = HashSet::new();
    header_set.insert(header::ACCEPT.to_string());
    header_set.insert(header::ACCEPT_CHARSET.to_string());
    header_set.insert(header::ACCEPT_ENCODING.to_string());
    header_set.insert(header::ACCEPT_LANGUAGE.to_string());
    header_set.insert(header::ACCEPT_RANGES.to_string());
    header_set.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS.to_string());
    header_set.insert(header::ACCESS_CONTROL_ALLOW_HEADERS.to_string());
    header_set.insert(header::ACCESS_CONTROL_ALLOW_METHODS.to_string());
    header_set.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN.to_string());
    header_set.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS.to_string());
    header_set.insert(header::ACCESS_CONTROL_MAX_AGE.to_string());
    header_set.insert(header::ACCESS_CONTROL_REQUEST_HEADERS.to_string());
    header_set.insert(header::ACCESS_CONTROL_REQUEST_METHOD.to_string());
    header_set.insert(header::AGE.to_string());
    header_set.insert(header::ALLOW.to_string());
    header_set.insert(header::ALT_SVC.to_string());
    header_set.insert(header::CACHE_CONTROL.to_string());
    header_set.insert(header::CONNECTION.to_string());
    header_set.insert(header::CONTENT_DISPOSITION.to_string());
    header_set.insert(header::CONTENT_ENCODING.to_string());
    header_set.insert(header::CONTENT_LANGUAGE.to_string());
    header_set.insert(header::CONTENT_LENGTH.to_string());
    header_set.insert(header::CONTENT_LOCATION.to_string());
    header_set.insert(header::CONTENT_RANGE.to_string());
    header_set.insert(header::CONTENT_SECURITY_POLICY.to_string());
    header_set.insert(header::CONTENT_SECURITY_POLICY_REPORT_ONLY.to_string());
    header_set.insert(header::CONTENT_TYPE.to_string());
    header_set.insert(header::DNT.to_string());
    header_set.insert(header::DATE.to_string());
    header_set.insert(header::ETAG.to_string());
    header_set.insert(header::EXPECT.to_string());
    header_set.insert(header::EXPIRES.to_string());
    header_set.insert(header::FORWARDED.to_string());
    header_set.insert(header::FROM.to_string());
    header_set.insert(header::HOST.to_string());
    header_set.insert(header::IF_MATCH.to_string());
    header_set.insert(header::IF_MODIFIED_SINCE.to_string());
    header_set.insert(header::IF_NONE_MATCH.to_string());
    header_set.insert(header::IF_RANGE.to_string());
    header_set.insert(header::IF_UNMODIFIED_SINCE.to_string());
    header_set.insert(header::LAST_MODIFIED.to_string());
    header_set.insert(header::LINK.to_string());
    header_set.insert(header::LOCATION.to_string());
    header_set.insert(header::MAX_FORWARDS.to_string());
    header_set.insert(header::ORIGIN.to_string());
    header_set.insert(header::PRAGMA.to_string());
    header_set.insert(header::PUBLIC_KEY_PINS.to_string());
    header_set.insert(header::PUBLIC_KEY_PINS_REPORT_ONLY.to_string());
    header_set.insert(header::RANGE.to_string());
    header_set.insert(header::REFERER.to_string());
    header_set.insert(header::REFERRER_POLICY.to_string());
    header_set.insert(header::REFRESH.to_string());
    header_set.insert(header::RETRY_AFTER.to_string());
    header_set.insert(header::SEC_WEBSOCKET_ACCEPT.to_string());
    header_set.insert(header::SEC_WEBSOCKET_EXTENSIONS.to_string());
    header_set.insert(header::SEC_WEBSOCKET_KEY.to_string());
    header_set.insert(header::SEC_WEBSOCKET_PROTOCOL.to_string());
    header_set.insert(header::SEC_WEBSOCKET_VERSION.to_string());
    header_set.insert(header::SERVER.to_string());
    header_set.insert(header::STRICT_TRANSPORT_SECURITY.to_string());
    header_set.insert(header::TE.to_string());
    header_set.insert(header::TRAILER.to_string());
    header_set.insert(header::TRANSFER_ENCODING.to_string());
    header_set.insert(header::UPGRADE.to_string());
    header_set.insert(header::UPGRADE_INSECURE_REQUESTS.to_string());
    header_set.insert(header::USER_AGENT.to_string());
    header_set.insert(header::VARY.to_string());
    header_set.insert(header::VIA.to_string());
    header_set.insert(header::WARNING.to_string());
    header_set.insert(header::X_CONTENT_TYPE_OPTIONS.to_string());
    header_set.insert(header::X_DNS_PREFETCH_CONTROL.to_string());
    header_set.insert(header::X_FRAME_OPTIONS.to_string());
    header_set.insert(header::X_XSS_PROTECTION.to_string());
    if let Ok(forwarded_header) = header::HeaderName::from_bytes(b"X-Forwarded-For") {
        header_set.insert(forwarded_header.to_string());
    }
    if let Ok(forwarded_header) = header::HeaderName::from_bytes(b"X-Request-Id") {
        header_set.insert(forwarded_header.to_string());
    }
    if let Ok(forwarded_header) = header::HeaderName::from_bytes(b"X-Amzn-Trace-Id") {
        header_set.insert(forwarded_header.to_string());
    }
    if let Ok(forwarded_header) = header::HeaderName::from_bytes(b"X-Download-Options") {
        header_set.insert(forwarded_header.to_string());
    }
    if let Ok(forwarded_header) = header::HeaderName::from_bytes(b"X-Evervault-Region") {
        header_set.insert(forwarded_header.to_string());
    }
    if let Ok(global_trx_id) = header::HeaderName::from_bytes(b"X-Global-Transaction-Id") {
        header_set.insert(global_trx_id.to_string());
    }
    header_set
}
