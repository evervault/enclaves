use std::time::Duration;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AcceptorConfig {
    pub max_concurrent_connections: usize,
    // Maximum connections allowed in the TLS handshake phase. Tracked separately from total
    // connections because the handshake is the expensive bit
    pub max_concurrent_handshakes: usize,
    pub handshake_timeout: Option<Duration>,
}

impl Default for AcceptorConfig {
    // The default is to process requests in series to match the current behavior.
    // This makes the concurrent behavior opt-in
    fn default() -> Self {
        Self {
            max_concurrent_connections: 1,
            max_concurrent_handshakes: 1,
            handshake_timeout: None,
        }
    }
}

impl AcceptorConfig {
    pub fn serial_compat() -> Self {
        Self::default()
    }

    pub fn concurrent_default() -> Self {
        Self {
            max_concurrent_connections: 1024,
            max_concurrent_handshakes: 64,
            handshake_timeout: Some(Duration::from_secs(10)),
        }
    }

    pub fn is_serial(&self) -> bool {
        self.max_concurrent_connections <= 1 && self.max_concurrent_handshakes <= 1
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_is_serial_profile() {
        let config = AcceptorConfig::default();
        assert_eq!(config.max_concurrent_connections, 1);
        assert_eq!(config.max_concurrent_handshakes, 1);
        assert!(config.handshake_timeout.is_none());
        assert!(config.is_serial());
    }

    #[test]
    fn serial_compat_matches_default() {
        let serial = AcceptorConfig::serial_compat();
        let default = AcceptorConfig::default();
        assert_eq!(
            serial.max_concurrent_connections,
            default.max_concurrent_connections
        );
        assert_eq!(
            serial.max_concurrent_handshakes,
            default.max_concurrent_handshakes
        );
        assert_eq!(serial.handshake_timeout, default.handshake_timeout);
    }

    #[test]
    fn concurrent_default_is_concurrent() {
        let config = AcceptorConfig::concurrent_default();
        assert!(config.max_concurrent_connections > 1);
        assert!(config.max_concurrent_handshakes > 1);
        assert!(config.handshake_timeout.is_some());
        assert!(!config.is_serial());
    }

    #[test]
    fn absent_block_deserialises_to_serial_default() {
        let config: AcceptorConfig = serde_json::from_str("{}").unwrap();
        assert!(config.is_serial());
        assert_eq!(config.max_concurrent_connections, 1);
        assert_eq!(config.max_concurrent_handshakes, 1);
        assert!(config.handshake_timeout.is_none());
    }

    #[test]
    fn full_block_deserialises_all_three_fields() {
        let raw = r#"{
            "max_concurrent_connections": 1024,
            "max_concurrent_handshakes": 64,
            "handshake_timeout": { "secs": 10, "nanos": 0 }
        }"#;
        let config: AcceptorConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(config.max_concurrent_connections, 1024);
        assert_eq!(config.max_concurrent_handshakes, 64);
        assert_eq!(config.handshake_timeout, Some(Duration::from_secs(10)));
        assert!(!config.is_serial());
    }

    #[test]
    fn partial_block_keeps_serial_defaults_for_absent_fields() {
        let raw = r#"{ "max_concurrent_connections": 512 }"#;
        let config: AcceptorConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(config.max_concurrent_connections, 512);
        assert_eq!(config.max_concurrent_handshakes, 1);
        assert!(config.handshake_timeout.is_none());
    }
}
