use cadence::{BufferedUdpMetricSink, QueuingMetricSink};
use cadence::{MetricError, StatsdClient};
use cadence_macros::{set_global_default, statsd_count, statsd_gauge};
use shared::ENCLAVE_STATSD_PORT;
use std::{io::Error, net::UdpSocket};
use thiserror::Error;

use crate::CageContext;

#[derive(Debug, Error)]
pub enum StatsError {
    #[error("Sys info error {0}")]
    SysInfoError(#[from] sys_info::Error),
    #[error("Metric error {0}")]
    MetricError(#[from] MetricError),
    #[error("IO error {0}")]
    IOError(#[from] Error),
}

macro_rules! publish_gauge {
    ($label:literal, $val:expr, $context:expr) => {
        statsd_gauge!(
          $label,
          $val,
          "cage_uuid" => &$context.cage_uuid,
          "app_uuid" => &$context.app_uuid
        );
    };
}

macro_rules! publish_count {
    ($label:literal, $val:expr, $context:expr) => {
        statsd_count!(
          $label,
          $val,
          "cage_uuid" => &$context.cage_uuid,
          "app_uuid" => &$context.app_uuid
        );
    };
}

pub struct StatsClient;

impl StatsClient {
    pub fn init() {
        if let Err(e) = Self::initialize_sink() {
            println!("Couldn't init statsd client: {e}");
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
        if let Ok(context) = CageContext::get() {
            publish_count!("decrypt.count", 1, context);
        }
    }

    pub fn record_encrypt() {
        if let Ok(context) = CageContext::get() {
            publish_count!("encrypt.count", 1, context);
        }
    }

    pub fn record_request() {
        if let Ok(context) = CageContext::get() {
            publish_count!("request.count", 1, context);
        }
    }

    pub fn record_system_metrics() {
        if let Err(e) = Self::try_record_system_metrics() {
            println!("Couldn't get system metrics: {e}");
        }
    }

    pub fn try_record_system_metrics() -> Result<(), StatsError> {
        let mem_info = sys_info::mem_info()?;
        let cpu = sys_info::loadavg()?;
        let cpu_num = sys_info::cpu_num()?;

        if let Ok(context) = CageContext::get() {
            publish_gauge!("memory.total", mem_info.total as f64, context);
            publish_gauge!("memory.avail", mem_info.avail as f64, context);
            publish_gauge!("memory.free", mem_info.total as f64, context);

            publish_gauge!("cpu.cores", cpu_num as f64, context);
            publish_gauge!("cpu.one", cpu.one, context);
            publish_gauge!("cpu.five", cpu.five, context);
            publish_gauge!("cpu.fifteen", cpu.fifteen, context);
        };
        Ok(())
    }
}
