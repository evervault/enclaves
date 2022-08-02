use tokio::io::{AsyncRead, AsyncWrite};

pub async fn pipe_streams<T1, T2>(mut src: T1, mut dest: T2) -> Result<(u64, u64), tokio::io::Error>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut src, &mut dest).await
}
