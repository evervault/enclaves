use cadence::{QueuingMetricSink, StatsdClient};
use cadence_macros::{set_global_default, statsd_count, statsd_gauge};
use shared::bridge::{Bridge, BridgeInterface, Direction};
use shared::stats::{BufferedLocalStatsSink, StatsError};
use shared::{publish_count, publish_count_dynamic_label, publish_gauge, INTERNAL_STATSD_PORT};
use std::fs;
use std::time::Duration;

use crate::EnclaveContext;

pub struct StatsClient;

impl StatsClient {
    pub async fn init() {
        match Self::initialize_sink().await {
            Err(e) => log::error!("Couldn't init statsd client: {e}"),
            Ok(_) => Self::schedule_system_metrics_reporter(),
        }
    }

    async fn initialize_sink() -> Result<(), StatsError> {
        let stream =
            Bridge::get_client_connection(INTERNAL_STATSD_PORT, Direction::EnclaveToHost).await?;
        // Downgrade to std TcpStream required to be compatible with the trait bounds of cadence which requires `std::io::Write`
        #[cfg(not(feature = "enclave"))]
        let stream = stream
            .into_std()
            .expect("Failed to downgrade tokio tcp stream to std");
        let statsd_sink = BufferedLocalStatsSink::from(stream);
        let queuing_sink = QueuingMetricSink::from(statsd_sink);
        let client = StatsdClient::from_sink("", queuing_sink);
        set_global_default(client);
        Ok(())
    }

    pub fn record_decrypt() {
        if let Ok(context) = EnclaveContext::get() {
            publish_count!("evervault.enclaves.decrypt.count", 1, context);
        }
    }

    fn get_file_descriptor_info() -> Result<(u64, u64, u64), StatsError> {
        let content = fs::read_to_string("/proc/sys/fs/file-nr")?;
        let parts: Vec<&str> = content.split_whitespace().collect();

        if parts.len() == 3 {
            let allocated: u64 = parts[0]
                .parse()
                .map_err(|_| StatsError::FDUsageParseError)?;
            let free: u64 = parts[1]
                .parse()
                .map_err(|_| StatsError::FDUsageParseError)?;
            let max: u64 = parts[2]
                .parse()
                .map_err(|_| StatsError::FDUsageParseError)?;
            Ok((allocated, free, max))
        } else {
            Err(StatsError::FDUsageReadError)
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

    fn try_record_system_metrics() -> Result<(), StatsError> {
        let mem_info =
            sys_info::mem_info().map_err(|e| log::error!("Couldn't obtain mem info: {e}"));
        let cpu = sys_info::loadavg().map_err(|e| log::error!("Couldn't obtain cpu info: {e}"));
        let cpu_num = sys_info::cpu_num().map_err(|e| log::error!("Couldn't obtain cpu num: {e}"));
        let fd_info = Self::get_file_descriptor_info()
            .map_err(|e| log::error!("Couldn't obtain fd info: {e}"));

        if let Ok(context) = EnclaveContext::get() {
            if let Ok(mem_info) = mem_info {
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
            }

            if let Ok(cpu_num) = cpu_num {
                publish_gauge!("evervault.enclaves.cpu.cores", cpu_num as f64, context);
            }

            if let Ok(cpu) = cpu {
                publish_gauge!("evervault.enclaves.cpu.one", cpu.one, context);
            }

            if let Ok((allocated, free, max)) = fd_info {
                publish_gauge!("evervault.enclaves.fd.allocated", allocated, context);
                publish_gauge!("evervault.enclaves.fd.free", free, context);
                publish_gauge!("evervault.enclaves.fd.max", max, context);
            }
        }

        Ok(())
    }

    fn schedule_system_metrics_reporter() {
        // Take interval in seconds from the SYSTEM_STATS_INTERVAL variable, defaulting to every minute.
        let interval = std::env::var("SYSTEM_STATS_INTERVAL")
            .ok()
            .and_then(|interval_str| interval_str.parse::<u64>().ok())
            .unwrap_or(60);

        tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval));

            loop {
                interval.tick().await;
                if let Err(e) = Self::try_record_system_metrics() {
                    log::error!("Couldn't get system metrics: {e}");
                }
            }
        });
    }
}
