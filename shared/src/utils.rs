use tokio::io::{AsyncRead, AsyncWrite};

fn is_low_signal_error(err: &tokio::io::Error) -> bool {
    let err_kind = err.kind();
    matches!(err_kind, tokio::io::ErrorKind::NotConnected)
        || matches!(err_kind, tokio::io::ErrorKind::ConnectionReset)
        || matches!(err_kind, tokio::io::ErrorKind::BrokenPipe)
}

pub async fn pipe_streams<T1, T2>(
    mut src: T1,
    mut dest: T2,
) -> Result<Option<(u64, u64)>, tokio::io::Error>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut src, &mut dest).await {
        Ok(bytes_written) => Ok(Some(bytes_written)),
        Err(e) if is_low_signal_error(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

pub struct HexSlice<'a>(&'a [u8]);

impl<'a> std::fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl<'a> std::fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<'a> std::convert::From<&'a [u8]> for HexSlice<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(slice)
    }
}

#[macro_export]
macro_rules! print_version {
    ($label:tt) => {
        if let Ok(version) = std::env::var("CARGO_PKG_VERSION") {
            log::info!("{} Version: {}", $label, version);
        }
    };
}

#[macro_export]
macro_rules! env_var_present_and_true {
    ($var_name:tt) => {
        match std::env::var($var_name) {
            Ok(s) if s.as_str() == "true" => true,
            _ => false,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::HexSlice;

    #[test]
    fn test_upper_hex_slice_formatting() {
        let slice: [u8; 2] = [255, 3];
        let hex_slice = HexSlice(slice.as_slice());
        let expected_hex = "FF03".to_string();
        assert_eq!(format!("{hex_slice:X}"), expected_hex);
    }

    #[test]
    fn test_lower_hex_slice_formatting() {
        let slice: [u8; 2] = [255, 90];
        let hex_slice = HexSlice(slice.as_slice());
        let expected_hex = "ff5a".to_string();
        assert_eq!(format!("{hex_slice:x}"), expected_hex);
    }
}
