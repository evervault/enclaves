use derive_builder::Builder;
use std::collections::HashSet;

use hyper::{
    header::{self, CONTENT_TYPE, USER_AGENT},
    http::HeaderValue,
    Body, HeaderMap, Request, Response,
};

#[allow(dead_code)]
#[derive(serde::Serialize, Clone, Debug, Builder)]
pub struct TrxContext {
    msg: String,
    uri: String,
    request_method: String,
    request_headers: Option<String>,
    user_agent: Option<String>,
    response_headers: Option<String>,
    response_code: Option<String>,
    cage_name: String,
    cage_uuid: String,
    app_uuid: String,
    team_uuid: String,
    n_decrypts: Option<u32>,
    content_type: Option<String>,
    response_content_type: Option<String>,
}

impl TrxContext {
    pub fn record_trx(mut self) {
        if self.response_code.is_none() {
            self.response_code = Some("ERR".to_string());
        }

        let json_log = serde_json::to_string(&self);
        //TODO - add feature flag check here to ship logs to config server instead of logging in dataplane
        // It should also use a mpsc channel to send to a different tokio task so it doesn't block the request if it fails
        if let Ok(log) = json_log {
            println!("{}", log);
        }
    }
}

impl TrxContextBuilder {
    fn new() -> TrxContextBuilder {
        TrxContextBuilder {
            msg: Some("Cage Transaction Complete".to_string()),
            uri: None,
            request_method: None,
            request_headers: None,
            user_agent: None,
            response_headers: None,
            response_code: None,
            cage_name: None,
            cage_uuid: None,
            team_uuid: None,
            app_uuid: None,
            n_decrypts: None,
            content_type: None,
            response_content_type: None,
        }
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
        self.response_code(Some(res.status().to_string()));
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
        self.request_headers(Some(convert_headers_to_string(headers)));
    }

    fn add_headers_to_response(&mut self, headers: &HeaderMap<HeaderValue>) {
        self.response_headers(Some(convert_headers_to_string(headers)));
    }

    pub fn can_build(&mut self) -> bool {
        self.uri.is_some()
            & self.cage_name.is_some()
            & self.cage_uuid.is_some()
            & self.request_method.is_some()
            & self.request_headers.is_some()
    }
}

fn convert_headers_to_string(headers: &HeaderMap<HeaderValue>) -> String {
    headers.iter().fold(String::new(), |mut acc, (key, value)| {
        if NON_SENSITIVE_HEADERS.contains(&key.to_string()) {
            let header_str = format!("{}: {}, ", key, value.to_str().unwrap());
            acc.push_str(&header_str);
        };
        acc
    })
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
