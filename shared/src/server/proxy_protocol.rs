use super::error::{ServerError, ServerResult};
pub use ppp::v2::Header as PPHeader;
use std::convert::TryFrom;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
const MIN_PROXY_PROTOCOL_HEADER_LEN: usize = 16;

pub struct AcceptedConn<S: AsyncRead + AsyncWrite> {
    inner: S,
    proxy_protocol: Option<PPHeader<'static>>,
    preread_buffer: Option<Vec<u8>>,
}

impl<S: AsyncRead + AsyncWrite + Sync> AcceptedConn<S> {
    fn new(
        inner: S,
        proxy_protocol: Option<PPHeader<'static>>,
        preread_buffer: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            proxy_protocol,
            preread_buffer,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Sync> AsyncRead for AcceptedConn<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(preread_buf) = this.preread_buffer.as_mut() {
            let len = std::cmp::min(preread_buf.len(), buf.remaining());
            buf.put_slice(&preread_buf[..len]);
            preread_buf.drain(..len);
            if preread_buf.is_empty() {
                this.preread_buffer = None;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Sync> AsyncWrite for AcceptedConn<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        let pinned_inner = std::pin::Pin::new(&mut self.get_mut().inner);
        pinned_inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        let pinned_inner = std::pin::Pin::new(&mut self.get_mut().inner);
        pinned_inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        let pinned_inner = std::pin::Pin::new(&mut self.get_mut().inner);
        pinned_inner.poll_shutdown(cx)
    }
}

pub async fn try_parse_proxy_protocol<S: AsyncRead + AsyncWrite + Unpin + Sync>(
    mut incoming_conn: S,
) -> ServerResult<AcceptedConn<S>> {
    let mut buf: Vec<u8> = Vec::with_capacity(MIN_PROXY_PROTOCOL_HEADER_LEN);
    let mut total_read_bytes = 0;
    loop {
        let read_len = incoming_conn.read_buf(&mut buf).await?;
        if read_len == 0 {
            let _ = incoming_conn.shutdown().await;
            return Err(ServerError::UnexpectedEOF);
        }
        total_read_bytes += read_len;

        let relevant_slice = (&buf[..total_read_bytes]).to_vec();
        let parsed = PPHeader::try_from(&relevant_slice[..]);
        match parsed {
            Ok(header) => {
                let owned_header = header.to_owned();
                drop(header);
                let _header_bytes: Vec<_> = buf.drain(..owned_header.len()).collect();

                return Ok(AcceptedConn::new(
                    incoming_conn,
                    Some(owned_header),
                    Some(buf),
                ));
            }
            // don't need to reserve more bytes for incomplete — will only throw on first read, so default buf size will be sufficient
            Err(ppp::v2::ParseError::Incomplete(_)) => {
                continue;
            }
            Err(ppp::v2::ParseError::Partial(_, required_bytes)) => {
                buf.reserve_exact(required_bytes);
            }
            Err(e) => {
                eprintln!("{e:?}");
                return Ok(AcceptedConn::new(incoming_conn, None, Some(buf)));
            }
        }
    }
}

pub trait ProxiedConnection: Sync {
    fn proxy_protocol(&self) -> Option<&PPHeader<'_>> {
        None
    }
    fn has_proxy_protocol(&self) -> bool {
        false
    }
}

impl<C: AsyncRead + AsyncWrite + Sync> ProxiedConnection for AcceptedConn<C> {
    fn proxy_protocol(&self) -> Option<&PPHeader> {
        self.proxy_protocol.as_ref()
    }

    fn has_proxy_protocol(&self) -> bool {
        self.proxy_protocol.is_some()
    }
}
