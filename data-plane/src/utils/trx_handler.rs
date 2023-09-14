use std::{collections::VecDeque, time::Duration};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use shared::logging::TrxContext;
use tokio::time::sleep;

use crate::config_client::ConfigClient;

enum LogHandlerMessageType {
    TickMsg,
    TrxMsg,
}

pub struct LogHandlerMessage {
    trx_log: Option<TrxContext>,
    msg_type: LogHandlerMessageType,
}

impl LogHandlerMessage {
    pub fn new_log_message(trx_log: TrxContext) -> Self {
        Self {
            trx_log: Some(trx_log),
            msg_type: LogHandlerMessageType::TrxMsg,
        }
    }

    pub fn new_tick_message() -> Self {
        Self {
            trx_log: None,
            msg_type: LogHandlerMessageType::TickMsg,
        }
    }
}

struct LogHandlerBuffer {
    config_client: ConfigClient,
    buffer: VecDeque<TrxContext>,
}

impl LogHandlerBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            config_client: ConfigClient::new(),
            buffer: VecDeque::with_capacity(capacity),
        }
    }

    pub fn get_size(&self) -> usize {
        self.buffer.len()
    }

    pub fn add_log(&mut self, log: TrxContext) {
        self.buffer.push_back(log)
    }

    // Removes logs from the buffer and sends them to the control plane
    pub async fn send_logs(&mut self) {
        let trx_logs: Vec<TrxContext> = self.buffer.drain(..).collect();
        if let Err(err) = self.config_client.post_trx_logs(trx_logs).await {
            log::error!("Failed to ship trx logs to control plane. {err:?}");
        };
    }
}

pub async fn start_log_handler(
    tx: UnboundedSender<LogHandlerMessage>,
    mut rx: UnboundedReceiver<LogHandlerMessage>,
) {
    //Start timer send messages to periodically clear buffer
    start_log_timer(tx);

    // Give buffer max capacity of 10 for space. Will flush on 5 but have capacity for more.
    let mut buffer = LogHandlerBuffer::new(10);

    while let Some(message) = rx.recv().await {
        match message.msg_type {
            LogHandlerMessageType::TickMsg => {
                let current_size = buffer.get_size();
                if current_size > 0 {
                    log::debug!("{current_size:?} logs in the buffer. Sending to control plane");
                    buffer.send_logs().await;
                };
                //No logs in the buffer. No op.
            }
            LogHandlerMessageType::TrxMsg => {
                if let Some(log) = message.trx_log {
                    buffer.add_log(log);
                };

                let current_size = buffer.get_size();
                if current_size >= 5 {
                    //Buffer size has multiple logs. Flush buffer and send to control plane
                    buffer.send_logs().await;
                }
                //Don't flush buffer yet with only a small amount logs
            }
        }
    }
}

fn start_log_timer(tx: UnboundedSender<LogHandlerMessage>) {
    tokio::spawn(async move {
        loop {
            //Wait five seconds
            sleep(Duration::from_millis(5000)).await;

            //Send tick message to handler
            if let Err(err) = tx.send(LogHandlerMessage::new_tick_message()) {
                log::error!("Failed sending trx tick message to trx handler. {err}")
            }
        }
    });
}
