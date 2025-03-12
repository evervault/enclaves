pub mod client;
pub mod proxy;

pub const INTERNAL_STATSD_PORT: u16 = 8125;
pub const EXTERNAL_STATSD_PORT: u16 = 8126;

#[cfg(not(feature = "enclave"))]
pub fn get_stats_target_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 20, 0, 6))
}

#[cfg(feature = "enclave")]
pub fn get_stats_target_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}
