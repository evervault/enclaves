//! Module containing all parsing logic for parsing incoming streams.
//! The data plane needs to support both HTTP and non-HTTP traffic.

use httparse::Status;
use hyper::Body;
use std::str::FromStr;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

const READ_TIMEOUT: usize = 10;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("I/O Error while parsing incoming request - {0}")]
    IoError(#[from] tokio::io::Error),
    #[error("Reached EOF while parsing incoming request")]
    UnexpectedEof,
    #[error("Timeout while reading from socket")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    Hyper(#[from] hyper::http::Error),
}

async fn read_from_stream<T: AsyncRead + Unpin>(
    stream: &mut T,
    buffer: &mut Vec<u8>,
) -> Result<usize, ParseError> {
    let chunk_size = stream.read(buffer).await?;
    if chunk_size > 0 {
        return Ok(chunk_size);
    } else {
        return Err(ParseError::UnexpectedEof);
    }
}

pub enum Incoming {
    HttpRequest(hyper::Request<hyper::Body>),
    NonHttpRequest(Vec<u8>),
}

pub async fn try_parse_http_request_from_stream<T: AsyncRead + Unpin>(
    stream: &mut T,
    target_port: u16,
) -> Result<Incoming, ParseError> {
    let mut buffer = Vec::new();

    loop {
        // Declare our empty buffers to read the parsed data into
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _ = read_from_stream(stream, &mut buffer).await?;

        match req.parse(&buffer) {
            Ok(Status::Complete(body_offset)) => {
                let request_header_map = build_header_map_for_request(&req.headers)?;
                let content_length = get_content_length_from_headers(&request_header_map);
                let req_uri = format!(
                    "http://127.0.0.1:{}{}",
                    target_port,
                    req.path.unwrap_or("/")
                );

                let complete_request = hyper::Request::builder()
                    .uri(req_uri)
                    .method(req.method.unwrap_or("GET"));

                if let Some(content_length) = content_length {
                    let mut body_buffer: Vec<u8> = buffer.drain(body_offset..).collect();
                    body_buffer.reserve(content_length - (buffer.len() - body_offset));
                    let request_body =
                        read_incoming_body_from_stream(content_length, stream, body_buffer).await?;
                    let mut complete_request = complete_request.body(request_body)?;
                    (*complete_request.headers_mut()) = request_header_map;
                    return Ok(Incoming::HttpRequest(complete_request));
                }
                let mut complete_request = complete_request.body(Body::empty())?;
                (*complete_request.headers_mut()) = request_header_map;
                return Ok(Incoming::HttpRequest(complete_request));
            }
            Ok(Status::Partial) => continue,
            Err(e) => {
                log::debug!("Error while parsing incoming traffic as HTTP - {e}");
                return Ok(Incoming::NonHttpRequest(buffer));
            }
        }
    }
}

fn build_header_map_for_request(
    headers: &[httparse::Header],
) -> Result<hyper::HeaderMap, hyper::http::Error> {
    let mut header_map = hyper::http::HeaderMap::new();
    for header in headers {
        header_map.insert(
            hyper::http::HeaderName::from_str(header.name)?,
            hyper::http::HeaderValue::from_bytes(header.value)?,
        );
    }
    Ok(header_map)
}

fn get_content_length_from_headers(header_map: &hyper::HeaderMap) -> Option<usize> {
    header_map
        .get(hyper::http::header::CONTENT_LENGTH)
        .and_then(|header_val| header_val.to_str().ok())
        .and_then(|content_len| content_len.parse::<usize>().ok())
}

async fn read_incoming_body_from_stream<T: AsyncRead + Unpin>(
    content_length: usize,
    stream: &mut T,
    mut buffer: Vec<u8>,
) -> Result<hyper::Body, ParseError> {
    while buffer.len() < content_length {
        let n_bytes_read = tokio::time::timeout(
            std::time::Duration::from_secs(READ_TIMEOUT as u64),
            stream.read(&mut buffer),
        )
        .await
        .map_err(ParseError::from)??;
        if n_bytes_read == 0 {
            return Err(ParseError::UnexpectedEof);
        }
    }
    Ok(hyper::Body::from(buffer))
}
