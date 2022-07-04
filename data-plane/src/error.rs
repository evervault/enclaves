use std::fmt;

pub enum Error {
    Crypto(String)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "{}", match self {
	    Error::Crypto(message) => message
	})
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "{}", self)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
