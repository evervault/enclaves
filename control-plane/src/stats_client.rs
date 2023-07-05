use cadence::{BufferedUdpMetricSink, QueuingMetricSink, StatsdClient};
use cadence_macros::{set_global_default, statsd_count};
use shared::{publish_count, stats::StatsError};
use std::net::{Ipv4Addr, UdpSocket};

use crate::configuration::CageContext;

pub struct StatsClient;

impl StatsClient {
    pub fn init() {
        if let Err(e) = Self::initialize_sink() {
            println!("Couldn't init statsd client: {e}");
        }
    }

    fn initialize_sink() -> Result<(), StatsError> {
        #[cfg(not(feature = "enclave"))]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(172, 20, 0, 6));
        #[cfg(feature = "enclave")]
        let target_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let udp_sink = BufferedUdpMetricSink::from((target_ip, 8125), socket)?;
        let queuing_sink = QueuingMetricSink::from(udp_sink);
        let client = StatsdClient::from_sink("", queuing_sink);
        set_global_default(client);
        Ok(())
    }

    pub fn record_requests_minute(rpm: i64) {
        let context = CageContext::from_env_vars();
        publish_count!("requests.minute", rpm, context);
    }
}
