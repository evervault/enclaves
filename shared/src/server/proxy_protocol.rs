use super::{
    error::{ServerError, ServerResult},
    Listener,
};
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
        opt_preread_buffer: Option<Vec<u8>>,
    ) -> Self {
        // if the preread buffer is empty, we don't need to store it
        let preread_buffer = match opt_preread_buffer.as_deref() {
            Some(buf) if !buf.is_empty() => opt_preread_buffer,
            _ => None,
        };
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

        let relevant_slice = (buf[..total_read_bytes]).to_vec();
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
            Err(_) => {
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

    fn get_remote_addr(&self) -> Option<String> {
        self.proxy_protocol()
            .and_then(|header| match header.addresses {
                ppp::v2::Addresses::IPv4(ipv4) => Some(ipv4.source_address.to_string()),
                ppp::v2::Addresses::IPv6(ipv6) => Some(ipv6.source_address.to_string()),
                _ => None,
            })
    }
}

impl<C: AsyncRead + AsyncWrite + Sync> ProxiedConnection for AcceptedConn<C> {
    fn proxy_protocol(&self) -> Option<&PPHeader<'_>> {
        self.proxy_protocol.as_ref()
    }

    fn has_proxy_protocol(&self) -> bool {
        self.proxy_protocol.is_some()
    }
}

pub struct ProxyProtocolServer<T: super::Listener> {
    inner: T,
}

#[async_trait::async_trait]
impl<T: Listener + Send> Listener for ProxyProtocolServer<T>
where
    <T as Listener>::Error: Into<ServerError>,
{
    type Connection = AcceptedConn<<T as Listener>::Connection>;
    type Error = ServerError;

    async fn accept(&mut self) -> Result<Self::Connection, Self::Error> {
        let conn = self.inner.accept().await.map_err(|e| e.into())?;
        let accepted_conn = try_parse_proxy_protocol(conn).await?;
        Ok(accepted_conn)
    }
}

impl<T: Listener + Send> std::convert::From<T> for ProxyProtocolServer<T> {
    fn from(value: T) -> Self {
        Self { inner: value }
    }
}

#[cfg(test)]
mod tests {
    use super::ProxiedConnection;
    use tokio::io::AsyncReadExt;
    use tokio_test::io::Builder;

    fn build_proxy_protocol_header() -> Vec<u8> {
        let header = ppp::v2::Builder::with_addresses(
            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
            ppp::v2::Protocol::Stream,
            (
                "1.2.3.4:80"
                    .parse::<std::net::SocketAddr>()
                    .expect("Infallible - hardcoded"),
                "5.6.7.8:443"
                    .parse::<std::net::SocketAddr>()
                    .expect("Infallible - hardcoded"),
            ),
        );
        header.build().expect("Infallible - hardcoded")
    }

    #[tokio::test]
    async fn test_parse_proxy_protocol() {
        let buf = build_proxy_protocol_header();
        let mut mock_builder = Builder::new();
        mock_builder.read(&buf[..]);
        let mut mock = mock_builder.build();
        let accepted_conn = super::try_parse_proxy_protocol(&mut mock).await.unwrap();
        let parsed_header = accepted_conn.proxy_protocol().unwrap();
        assert_eq!(&buf[..], parsed_header.header.as_ref());
    }

    #[tokio::test]
    async fn test_parse_invalid_proxy_protocol() {
        let buf = build_proxy_protocol_header();
        let mut mock_builder = Builder::new();
        mock_builder.read(&buf[..buf.len() - 10]);
        let mut mock = mock_builder.build();
        let parse_result = super::try_parse_proxy_protocol(&mut mock).await;
        assert!(parse_result.is_err());
    }

    #[tokio::test]
    async fn test_read_from_socket_after_proxy_parse() {
        use tokio::io::AsyncReadExt;
        let buf = build_proxy_protocol_header();
        let mut mock_builder = Builder::new();
        mock_builder.read(&buf[..]);
        let client_hello = b"TLS Client Hello";
        mock_builder.read(client_hello);
        let mut mock = mock_builder.build();
        let mut accepted_conn: crate::server::proxy_protocol::AcceptedConn<
            &mut tokio_test::io::Mock,
        > = super::try_parse_proxy_protocol(&mut mock).await.unwrap();
        let parsed_header = accepted_conn.proxy_protocol().unwrap();
        assert_eq!(&buf[..], parsed_header.header.as_ref());

        // Validate that subsequent bytes are uneffected
        let mut read_buf = Vec::with_capacity(client_hello.len());
        accepted_conn.read_buf(&mut read_buf).await.unwrap();
        assert_eq!(client_hello, &read_buf[..]);
    }

    #[tokio::test]
    async fn test_parsing_with_valid_proxy_header() {
        let buf = build_proxy_protocol_header();
        let mut mock_builder = Builder::new();
        mock_builder.read(&buf[..]);
        let mut mock = mock_builder.build();
        let accepted_conn: crate::server::proxy_protocol::AcceptedConn<&mut tokio_test::io::Mock> =
            super::try_parse_proxy_protocol(&mut mock).await.unwrap();
        assert!(accepted_conn.has_proxy_protocol());
    }

    #[tokio::test]
    async fn test_parsing_with_invalid_proxy_header() {
        let mut buf = build_proxy_protocol_header();
        let mut mock_builder = Builder::new();
        // remove 13 bytes off the end of the proxy protocol header so it's incomplete
        let _: Vec<_> = buf.drain(..buf.len() - 13).collect();

        mock_builder.read(&buf[..]);

        // put some dummy data in the socket
        let dummy_data = [1_u8; 20].to_vec();
        mock_builder.read(&dummy_data[..]);
        let mut mock = mock_builder.build();
        let parse_result = super::try_parse_proxy_protocol(&mut mock).await;

        // Should still be able to read from the socket
        assert!(parse_result.is_ok());
        let mut accepted_conn = parse_result.unwrap();
        // no proxy protocol parsed for this connection
        assert!(!accepted_conn.has_proxy_protocol());
        let mut read_buf = Vec::with_capacity(20);
        // reading to EOF should return us everything from the socket including the incomplete proxy protocol
        accepted_conn.read_to_end(&mut read_buf).await.unwrap();
        let entire_content = [buf, dummy_data].concat();
        assert_eq!(&entire_content[..], &read_buf[..]);
    }
}
