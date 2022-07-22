use tokio::io::{AsyncRead, AsyncWrite};

pub async fn pipe_streams<T1, T2>(src: T1, dest: T2) -> Result<(u64, u64), tokio::io::Error>
where
    T1: AsyncRead + AsyncWrite,
    T2: AsyncRead + AsyncWrite,
{
    let (mut src_reader, mut src_writer) = tokio::io::split(src);
    let (mut dest_reader, mut dest_writer) = tokio::io::split(dest);

    tokio::try_join!(
        tokio::io::copy(&mut src_reader, &mut dest_writer),
        tokio::io::copy(&mut dest_reader, &mut src_writer)
    )
}
