use crate::configuration::EnclaveContext;
use super::INTERNAL_METRIC_PORT;
use cadence::{BufferedUdpMetricSink, QueuingMetricSink, StatsdClient};
use cadence_macros::{set_global_default, statsd_count};
use shared::{publish_count, stats::StatsError};
use std::net::UdpSocket;

pub struct StatsClient;

impl StatsClient {
    pub fn init() {
        if let Err(e) = Self::initialize_sink() {
            log::error!("Couldn't init statsd client: {e}");
        }
    }

    fn initialize_sink() -> Result<(), StatsError> {
        let target_ip = super::get_stats_target_ip();
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let udp_sink = BufferedUdpMetricSink::from((target_ip, INTERNAL_METRIC_PORT), socket)?;
        let queuing_sink = QueuingMetricSink::from(udp_sink);
        let client = StatsdClient::from_sink("", queuing_sink);
        set_global_default(client);
        Ok(())
    }

    pub fn record_request() {
        let context = EnclaveContext::from_env_vars();
        publish_count!("request.count", 1, context);
    }
}