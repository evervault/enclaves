use std::io::Error;

use cadence::MetricError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatsError {
    #[error("Sys info error {0}")]
    SysInfoError(#[from] sys_info::Error),
    #[error("Metric error {0}")]
    MetricError(#[from] MetricError),
    #[error("IO error {0}")]
    IOError(#[from] Error),
    #[error("Couldn't parse file descriptor values info from /proc/sys/fs/file-nr")]
    FDUsageParseError,
    #[error("Couldn't read file descriptor info from /proc/sys/fs/file-nr")]
    FDUsageReadError,
}

#[macro_export]
macro_rules! publish_gauge {
    ($label:literal, $val:expr, $context:expr) => {
        statsd_gauge!(
          $label,
          $val,
          "enclave_uuid" => &$context.uuid,
          "app_uuid" => &$context.app_uuid
        );
    };
}

#[macro_export]
macro_rules! publish_count {
    ($label:literal, $val:expr, $context:expr) => {
        statsd_count!(
          $label,
          $val,
          "enclave_uuid" => &$context.uuid,
          "app_uuid" => &$context.app_uuid
        );
    };
}

#[macro_export]
macro_rules! publish_count_dynamic_label {
    ($label:expr, $val:expr, $context:expr) => {
        statsd_count!(
          $label,
          $val,
          "enclave_uuid" => &$context.uuid,
          "app_uuid" => &$context.app_uuid
        );
    };
}
