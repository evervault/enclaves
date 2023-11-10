pub mod parse;

use hyper::http::header::HeaderValue;

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
