use std::{
    io::{Error, Write},
    sync::Mutex,
};

use cadence::{
    ext::{MultiLineWriter, SocketStats},
    MetricError, MetricSink,
};
use thiserror::Error;

use crate::server;

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
    #[error("Failed to create connection: {0}")]
    ServerError(#[from] server::error::ServerError),
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

#[derive(Debug)]
pub struct LocalSink<T> {
    inner: T,
    stats: SocketStats,
}

impl<T: Write> LocalSink<T> {
    fn new(stats: SocketStats, stream: T) -> Self {
        Self {
            stats,
            inner: stream,
        }
    }
}

impl<T: Write> Write for LocalSink<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stats.update(self.inner.write(buf), buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const DEFAULT_BUFFER_SIZE: usize = 512;

#[derive(Debug)]
pub struct BufferedLocalStatsSink<T: Write> {
    stats: SocketStats,
    buffer: Mutex<MultiLineWriter<LocalSink<T>>>,
}

impl<T: Write> std::convert::From<T> for BufferedLocalStatsSink<T> {
    fn from(value: T) -> Self {
        let stats = SocketStats::default();
        let sink = LocalSink::new(stats.clone(), value);
        let buffer_size = std::env::var("STATS_BUFFER_SIZE")
            .ok()
            .and_then(|buffer_size| buffer_size.parse().ok())
            .unwrap_or(DEFAULT_BUFFER_SIZE);

        Self {
            stats,
            buffer: Mutex::new(MultiLineWriter::new(sink, buffer_size)),
        }
    }
}

impl<T: Write> MetricSink for BufferedLocalStatsSink<T> {
    fn emit(&self, metric: &str) -> std::io::Result<usize> {
        let mut writer = self.buffer.lock().unwrap();
        writer.write(metric.as_bytes())
    }

    fn flush(&self) -> std::io::Result<()> {
        let mut writer = self.buffer.lock().unwrap();
        writer.flush()
    }

    fn stats(&self) -> cadence::SinkStats {
        (&self.stats).into()
    }
}
