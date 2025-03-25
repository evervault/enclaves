pub mod client;
pub mod proxy;

/// Port with statsd listener for internal metrics
pub const INTERNAL_METRIC_PORT: u16 = 8125;
/// Port with statsd listener for external customer metrics
pub const EXTERNAL_METRIC_PORT: u16 = 8126;

#[cfg(not(feature = "enclave"))]
pub fn get_stats_target_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 20, 0, 6))
}

#[cfg(feature = "enclave")]
pub fn get_stats_target_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}