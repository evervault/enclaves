use chrono::SecondsFormat;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, time::SystemTime};

use hyper::{
    header::{self, CONTENT_TYPE, USER_AGENT},
    http::HeaderValue,
    Body, HeaderMap, Request, Response, Uri,
};

use rand::{thread_rng, Rng};

use env_logger::Env;
pub fn init_env_logger() {
    let env = Env::default().filter_or("EV_CAGE_LOG", "info");
    env_logger::init_from_env(env);
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone, Debug, Builder, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrxContext {
    txid: String,
    ts: String,
    msg: String,
    uri: Option<String>,
    r#type: String,
    request_method: Option<String>,
    #[builder(default)]
    remote_ip: Option<String>,
    #[builder(default)]
    request_headers: Option<String>,
    #[builder(default)]
    user_agent: Option<String>,
    #[builder(default)]
    response_headers: Option<String>,
    #[builder(default)]
    response_code: Option<String>,
    #[builder(default)]
    status_group: Option<String>,
    pub cage_name: String,
    pub cage_uuid: String,
    pub app_uuid: String,
    pub team_uuid: String,
    #[builder(default)]
    n_decrypted_fields: Option<u32>,
    #[builder(default)]
    content_type: Option<String>,
    #[builder(default)]
    response_content_type: Option<String>,
    #[builder(default)]
    elapsed: Option<f64>,
    request_type: String,
}

impl TrxContext {
    pub fn record_trx(mut self) {
        if self.response_code.is_none() {
            self.response_code = Some("ERR".to_string());
        }
        let json_log = serde_json::to_string(&self);

        if let Ok(log) = json_log {
            println!("{log}");
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

pub enum RequestType {
    HTTP,
    Websocket,
    TCP,
}

impl From<RequestType> for String {
    fn from(val: RequestType) -> String {
        match val {
            RequestType::HTTP => "HTTP".to_string(),
            RequestType::TCP => "TCP".to_string(),
            RequestType::Websocket => "Websocket".to_string(),
        }
    }
}

impl TrxContextBuilder {
    fn new(request_type: RequestType) -> TrxContextBuilder {
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
            status_group: None,
            cage_name: None,
            cage_uuid: None,
            team_uuid: None,
            app_uuid: None,
            n_decrypted_fields: None,
            content_type: None,
            response_content_type: None,
            elapsed: None,
            remote_ip: None,
            request_type: Some(request_type.into()),
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
        request_type: RequestType,
    ) -> Self {
        let mut trx_context = Self::new(request_type);
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

    pub fn add_status_and_group(&mut self, status_code: u16) {
        let status_group = StatusGroup::from_u16(status_code).map(|group| format!("{group}"));
        self.status_group(status_group);
        self.response_code(Some(status_code.to_string()));
    }

    pub fn add_req_to_trx_context(&mut self, req: &Request<Body>, trusted_headers: &[String]) {
        self.uri(Some(build_log_uri(req.uri())));
        self.request_method(Some(req.method().to_string()));
        self.add_headers_to_request(req.headers(), trusted_headers);

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

    pub fn add_res_to_trx_context(&mut self, res: &Response<Body>, trusted_headers: &[String]) {
        self.add_status_and_group(res.status().as_u16());
        self.add_headers_to_response(res.headers(), trusted_headers);

        //Pull out content type
        if let Some(content_type) = res.headers().get(CONTENT_TYPE) {
            let content_type_str = content_type
                .to_str()
                .expect("Infallible - Failed to convert HeaderValue of ContentType to String");
            self.response_content_type(Some(content_type_str.into()));
        }
    }

    fn format_headers(headers: &[httparse::Header<'_>]) -> Option<String> {
        let mut map = Map::new();
        for header in headers {
            map.insert(
                header.name.to_string(),
                std::str::from_utf8(header.value).ok().into(),
            );
        }
        serde_json::to_string(&map).ok()
    }

    pub fn add_httparse_to_trx(
        &mut self,
        authorized: bool,
        request: Option<httparse::Request<'_, '_>>,
        remote_ip: Option<String>,
    ) {
        if let Some(req) = request {
            self.uri(req.path.map(|s| s.to_string()));
            self.request_method(req.method.map(|s| s.to_string()));
            self.request_headers(Self::format_headers(req.headers));
        };
        if !authorized {
            self.add_status_and_group(401);
        }
        self.remote_ip(remote_ip);
    }

    fn add_headers_to_request(
        &mut self,
        headers: &HeaderMap<HeaderValue>,
        trusted_headers: &[String],
    ) {
        let headers_map: Map<String, Value> = convert_headers_to_map(headers, trusted_headers);
        if let Ok(headers_string) = serde_json::to_string(&headers_map) {
            self.request_headers(Some(headers_string));
        }
    }

    fn add_headers_to_response(
        &mut self,
        headers: &HeaderMap<HeaderValue>,
        trusted_headers: &[String],
    ) {
        let headers_map = convert_headers_to_map(headers, trusted_headers);
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

fn is_trusted_header(trusted_headers: &[String], header_key: &str) -> bool {
    // Prevent sensitive headers from being logged
    if SENSITIVE_HEADERS.contains(header_key) {
        return false;
    }
    if NON_SENSITIVE_HEADERS.contains(header_key) {
        return true;
    }
    trusted_headers.iter().any(|trusted_header| {
        if trusted_header.ends_with('*') {
            return header_key.starts_with(&trusted_header[..trusted_header.len() - 1]);
        }
        header_key == trusted_header
    })
}

fn convert_headers_to_map(
    headers: &HeaderMap<HeaderValue>,
    trusted_headers: &[String],
) -> Map<String, Value> {
    let mut tracked_headers: Map<String, Value> = Map::new();
    for (header_key, header_value) in headers {
        match header_value.to_str() {
            Ok(header_value_str) if is_trusted_header(trusted_headers, header_key.as_str()) => {
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

fn build_log_uri(uri: &Uri) -> String {
    if let Some(query) = uri.query() {
        format!("{}?{}", uri.path(), query)
    } else {
        uri.path().to_string()
    }
}

lazy_static::lazy_static!(
    pub static ref NON_SENSITIVE_HEADERS: HashSet<String> = create_non_sensitive_header_set();
    pub static ref SENSITIVE_HEADERS: HashSet<String> = create_sensitive_header_set();
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

fn create_sensitive_header_set() -> HashSet<String> {
    let mut header_set = HashSet::new();
    header_set.insert(header::AUTHORIZATION.to_string());
    header_set.insert(header::PROXY_AUTHORIZATION.to_string());
    if let Ok(api_key) = header::HeaderName::from_bytes(b"Api-Key") {
        header_set.insert(api_key.to_string());
    }
    header_set
}

pub enum StatusGroup {
    Information,
    Success,
    Redirection,
    RequestErr,
    ServerErr,
}

impl StatusGroup {
    pub fn from_u16(val: u16) -> Option<Self> {
        let prefix = if val < 200 {
            StatusGroup::Information
        } else if val < 300 {
            StatusGroup::Success
        } else if val < 400 {
            StatusGroup::Redirection
        } else if val < 500 {
            StatusGroup::RequestErr
        } else if val < 600 {
            StatusGroup::ServerErr
        } else {
            return None;
        };
        Some(prefix)
    }
}

impl std::fmt::Display for StatusGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str_prefix = match self {
            Self::Information => "1XX",
            Self::Success => "2XX",
            Self::Redirection => "3XX",
            Self::RequestErr => "4XX",
            Self::ServerErr => "5XX",
        };
        write!(f, "{str_prefix}")
    }
}

#[cfg(test)]
mod test {
    use super::{is_trusted_header, TrxContext, TrxContextBuilder};

    #[test]
    fn test_create_non_http_log() {
        let mut headers = vec![
            httparse::Header {
                name: "test",
                value: "value".as_bytes(),
            },
            httparse::Header {
                name: "anotherTest",
                value: "value".as_bytes(),
            },
        ];
        let request = httparse::Request {
            method: Some("GET"),
            path: Some("/hello"),
            version: None,
            headers: &mut headers,
        };

        let mut trx = TrxContextBuilder::new(super::RequestType::Websocket);
        trx.app_uuid("123".to_string());
        trx.team_uuid("123".to_string());
        trx.cage_uuid("123".to_string());
        trx.cage_name("name".to_string());
        trx.add_httparse_to_trx(true, Some(request), Some("1.1.1.1".to_string()));
        let log = trx.build().unwrap();

        let expected_log = TrxContext {
            txid: trx.txid.unwrap(),
            ts: trx.ts.unwrap(),
            msg: "Cage Transaction Complete".to_owned(),
            uri: Some("/hello".to_string()),
            r#type: "cage_trx".to_string(),
            request_method: Some("GET".to_string()),
            remote_ip: Some("1.1.1.1".to_string()),
            request_headers: Some("{\"anotherTest\":\"value\",\"test\":\"value\"}".to_string()),
            user_agent: None,
            response_headers: None,
            response_code: None,
            status_group: None,
            cage_name: "name".to_string(),
            cage_uuid: "123".to_string(),
            app_uuid: "123".to_string(),
            team_uuid: "123".to_string(),
            n_decrypted_fields: None,
            content_type: None,
            response_content_type: None,
            elapsed: None,
            request_type: super::RequestType::Websocket.into(),
        };
        assert_eq!(log, expected_log);
    }

    #[test]
    fn test_trusted_headers_matching() {
        let trusted_headers = vec!["x-evervault-*".to_string(), "x-error-code".to_string()];

        let ev_debug_header = hyper::header::HeaderName::from_bytes(b"X-Evervault-Debug").unwrap();
        assert!(is_trusted_header(
            &trusted_headers,
            ev_debug_header.as_str()
        ));
        let error_code_header = hyper::header::HeaderName::from_bytes(b"X-Error-Code").unwrap();
        assert!(is_trusted_header(
            &trusted_headers,
            error_code_header.as_str()
        ));
        assert!(!is_trusted_header(&trusted_headers, "x-error-debug"));
        assert!(!is_trusted_header(&trusted_headers, "foo-bar"));

        // Block sensitive headers
        let api_key_header = hyper::header::HeaderName::from_bytes(b"api-key").unwrap();
        assert!(!is_trusted_header(
            &trusted_headers,
            api_key_header.as_str()
        ));
        assert!(!is_trusted_header(
            &trusted_headers,
            hyper::header::AUTHORIZATION.as_str()
        ));
    }

    #[test]
    fn test_sensitive_header_check_in_trusted_headers() {
        let trusted_headers = vec!["api-key".to_string(), "authorization".to_string()];
        // Block sensitive headers
        let api_key_header = hyper::header::HeaderName::from_bytes(b"api-key").unwrap();
        assert!(!is_trusted_header(
            &trusted_headers,
            api_key_header.as_str()
        ));
        assert!(!is_trusted_header(
            &trusted_headers,
            hyper::header::AUTHORIZATION.as_str()
        ));
    }

    use super::{build_log_uri, Uri};
    #[test]
    fn test_uri_formatting() {
        let path_and_query = "/path?query=true".to_string();
        let uri = Uri::builder()
            .scheme("https")
            .authority("cages.evervault.com")
            .path_and_query(&path_and_query)
            .build()
            .unwrap();
        assert_eq!(path_and_query, build_log_uri(&uri));

        let path_only = "/path".to_string();
        let uri = Uri::builder()
            .scheme("https")
            .authority("cages.evervault.com")
            .path_and_query(&path_only)
            .build()
            .unwrap();
        assert_eq!(path_only, build_log_uri(&uri));

        let base_path = "/".to_string();
        let uri = Uri::builder()
            .scheme("https")
            .authority("cages.evervault.com")
            .path_and_query(&base_path)
            .build()
            .unwrap();
        assert_eq!(base_path, build_log_uri(&uri));

        let base_query = "?query".to_string();
        let uri = Uri::builder()
            .scheme("https")
            .authority("cages.evervault.com")
            .path_and_query(&base_query)
            .build()
            .unwrap();
        assert_eq!(format!("/{}", base_query), build_log_uri(&uri));
    }
}
