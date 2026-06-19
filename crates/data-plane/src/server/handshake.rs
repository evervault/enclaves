use async_trait::async_trait;
use shared::server::proxy_protocol::{try_parse_proxy_protocol, AcceptedConn, ProxiedConnection};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::server::error::TlsError;

// Maps a raw connection into a high level connection object ready to be served.
// This abstracts away the PROXY protocol parsing and TLS handshake so both can move off the accept
// loop and be bound by the same handshake timeout
#[async_trait]
pub trait Handshaker<Raw>: Send + Sync {
    type Output: AsyncRead + AsyncWrite + ProxiedConnection + Send + Unpin + 'static;
    async fn handshake(&self, raw: Raw) -> Result<Self::Output, TlsError>;
}

// Production implementation of the Handshaker, handles both PROXY protocol and TLS
#[derive(Clone)]
pub struct TlsHandshaker {
    tls_acceptor: TlsAcceptor,
}

impl TlsHandshaker {
    pub fn new(tls_acceptor: TlsAcceptor) -> Self {
        Self { tls_acceptor }
    }
}

#[async_trait]
impl<Raw> Handshaker<Raw> for TlsHandshaker
where
    Raw: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    type Output = TlsStream<AcceptedConn<Raw>>;

    async fn handshake(&self, raw: Raw) -> Result<Self::Output, TlsError> {
        let accepted_conn = try_parse_proxy_protocol(raw).await?;
        let tls_conn = self.tls_acceptor.accept(accepted_conn).await?;
        Ok(tls_conn)
    }
}
