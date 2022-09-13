use tokio::io::{AsyncRead, AsyncWrite};

pub async fn pipe_streams<T1, T2>(mut src: T1, mut dest: T2) -> Result<(u64, u64), tokio::io::Error>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut src, &mut dest).await
}

pub struct HexSlice<'a>(&'a [u8]);

impl<'a> std::fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<'a> std::fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
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
            println!("{} Version: {version}", $label);
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
        assert_eq!(format!("{:X}", hex_slice), expected_hex);
    }

    #[test]
    fn test_lower_hex_slice_formatting() {
        let slice: [u8; 2] = [255, 90];
        let hex_slice = HexSlice(slice.as_slice());
        let expected_hex = "ff5a".to_string();
        assert_eq!(format!("{:x}", hex_slice), expected_hex);
    }
}
