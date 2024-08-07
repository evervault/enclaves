use cadence::StatsdClient;
use cadence::{BufferedUdpMetricSink, QueuingMetricSink};
use cadence_macros::{set_global_default, statsd_count, statsd_gauge};
use shared::stats::StatsError;
use shared::{publish_count, publish_count_dynamic_label, publish_gauge, ENCLAVE_STATSD_PORT};
use std::net::UdpSocket;

use crate::EnclaveContext;

pub struct StatsClient;

impl StatsClient {
    pub fn init() {
        if let Err(e) = Self::initialize_sink() {
            log::error!("Couldn't init statsd client: {e}");
        }
    }

    fn initialize_sink() -> Result<(), StatsError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let udp_sink = BufferedUdpMetricSink::from(("127.0.0.1", ENCLAVE_STATSD_PORT), socket)?;
        let queuing_sink = QueuingMetricSink::from(udp_sink);
        let client = StatsdClient::from_sink("", queuing_sink);
        set_global_default(client);
        Ok(())
    }

    pub fn record_decrypt() {
        if let Ok(context) = EnclaveContext::get() {
            publish_count!("evervault.enclaves.decrypt.count", 1, context);
        }
    }

    pub fn record_encrypt() {
        if let Ok(context) = EnclaveContext::get() {
            publish_count!("evervault.enclaves.encrypt.count", 1, context);
        }
    }

    pub fn record_cert_order(provider: &str, success: bool) {
        if let Ok(context) = EnclaveContext::get() {
            let success_key = if success { "success" } else { "failure" };
            let key = format!("{}.{}.count", provider, success_key);
            publish_count_dynamic_label!(key.as_str(), 1, context);
        }
    }

    pub fn record_system_metrics() {
        if let Err(e) = Self::try_record_system_metrics() {
            log::error!("Couldn't get system metrics: {e}");
        }
    }

    pub fn try_record_system_metrics() -> Result<(), StatsError> {
        let mem_info = sys_info::mem_info()?;
        let cpu = sys_info::loadavg()?;
        let cpu_num = sys_info::cpu_num()?;

        if let Ok(context) = EnclaveContext::get() {
            publish_gauge!(
                "evervault.enclaves.memory.total",
                mem_info.total as f64,
                context
            );
            publish_gauge!(
                "evervault.enclaves.memory.avail",
                mem_info.avail as f64,
                context
            );
            publish_gauge!("evervault.enclaves.cpu.cores", cpu_num as f64, context);
            publish_gauge!("evervault.enclaves.cpu.one", cpu.one, context);
        };
        Ok(())
    }
}
