use std::{io::{Error, Write}, sync::Mutex};
use crate::{server::CID, INTERNAL_STATSD_PORT, EXTERNAL_STATSD_PORT};
use cadence::{ext::{MultiLineWriter, SocketStats}, MetricError, MetricSink};
use tokio_vsock::VsockStream;
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

pub const INTERNAL_STATS_PROXY_ADDRESS: (u16, CID) = (INTERNAL_STATSD_PORT, CID::Parent);
pub const EXTERNAL_STATS_PROXY_ADDRESS: (u16, CID) = (EXTERNAL_STATSD_PORT, CID::Parent);

#[derive(Debug)]
pub struct VsockSink {
  inner: VsockStream,
  stats: SocketStats
}

impl VsockSink {
  fn new(stats: SocketStats, stream: VsockStream) -> Self {
    Self{ 
      stats,
      inner: stream
    }
  }
}

impl Write for VsockSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stats.update(self.inner.write(buf), buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const DEFAULT_BUFFER_SIZE: usize = 512;

#[derive(Debug)]
pub struct BufferedVsockStatsSink {
  stats: SocketStats,
  buffer: Mutex<MultiLineWriter<VsockSink>>
}

impl std::convert::From<VsockStream> for BufferedVsockStatsSink {
    fn from(value: VsockStream) -> Self {
        let stats = SocketStats::default();
        let vsock_stream = VsockSink::new(stats.clone(), value);
        Self {
          stats,
          buffer: Mutex::new(MultiLineWriter::new(vsock_stream, DEFAULT_BUFFER_SIZE))
        }
    }
}

impl MetricSink for BufferedVsockStatsSink {
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