pub mod parse;

use bytes::Bytes;
use hyper::{
    http::header::{HeaderName, HeaderValue, InvalidHeaderName},
    Body, HeaderMap, Request, Response,
};
use std::str::FromStr;

pub struct RemoteIp(pub String);

pub enum EncodingError {
    UnknownEncoding,
}

#[derive(Clone, Debug)]
pub enum ContentEncoding {
    Gzip,
    Br, //brotli
}

impl std::convert::TryFrom<&HeaderValue> for ContentEncoding {
    type Error = EncodingError;
    fn try_from(val: &HeaderValue) -> Result<Self, Self::Error> {
        let encoding = match val.as_bytes() {
            b"br" => Self::Br,
            b"gzip" => Self::Gzip,
            _ => return Err(EncodingError::UnknownEncoding),
        };
        Ok(encoding)
    }
}

pub async fn request_to_bytes(request: Request<Body>) -> Vec<u8> {
    let mut bytes = Vec::new();

    let (req_info, req_body) = request.into_parts();

    let path = req_info
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let status_line = format!("{} {} {:?}\r\n", req_info.method, path, req_info.version);
    bytes.extend_from_slice(status_line.as_bytes());

    for (header, val) in req_info.headers.iter() {
        let header_str = format!("{}: {}\r\n", header.as_str(), val.to_str().unwrap_or(""));
        bytes.extend_from_slice(header_str.as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");

    let body_bytes: Bytes = hyper::body::to_bytes(req_body)
        .await
        .unwrap_or_else(|_| Bytes::new());

    bytes.extend_from_slice(&body_bytes);

    bytes
}

pub async fn response_to_bytes(response: Response<Body>) -> Vec<u8> {
    let mut bytes = Vec::new();

    let status_line = format!(
        "{:?} {} {}\r\n",
        response.version(),
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    );
    bytes.extend_from_slice(status_line.as_bytes());

    for (header_name, header_value) in response.headers() {
        let header_str = format!(
            "{}: {}\r\n",
            header_name.as_str(),
            header_value.to_str().unwrap_or("")
        );
        bytes.extend_from_slice(header_str.as_bytes());
    }

    bytes.extend_from_slice(b"\r\n");

    let body_bytes: Bytes = hyper::body::to_bytes(response.into_body())
        .await
        .unwrap_or_else(|_| Bytes::new());

    bytes.extend_from_slice(&body_bytes);

    bytes
}

fn build_header_value_from_str(header_val: &str) -> HeaderValue {
    HeaderValue::from_str(header_val).expect("Unable to create HeaderValue from str")
}

pub fn append_or_insert_header(
    header: &str,
    header_map: &mut HeaderMap,
    value: &str,
) -> std::result::Result<(), InvalidHeaderName> {
    let header_name = HeaderName::from_str(header)?;
    if let Some(header_val) = header_map
        .get(&header_name)
        .and_then(|header_val| header_val.to_str().ok())
    {
        let updated_header = format!("{header_val}, {value}");
        header_map.insert(header_name, build_header_value_from_str(&updated_header));
    } else {
        header_map.insert(header_name, build_header_value_from_str(value));
    }
    Ok(())
}

fn add_remote_ip_to_forwarded_for_header(header_map: &mut HeaderMap, remote_ip: &str) {
    let _ = append_or_insert_header("X-Forwarded-For", header_map, remote_ip);
    let _ = append_or_insert_header("X-Forwarded-Proto", header_map, "https");
    let forwarded_header = format!("for={remote_ip};proto=https");
    let _ = append_or_insert_header("Forwarded", header_map, &forwarded_header);
}
