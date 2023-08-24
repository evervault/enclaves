use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcmeServerError {
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
}

pub type Result<T> = std::result::Result<T, AcmeServerError>;
