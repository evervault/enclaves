use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Debug)]
pub struct Diagnostic {
    label: String,
    data: serde_json::Value,
}

pub trait Diagnosable {
    fn sender(&self) -> Option<DiagnosticSender>;
    fn label() -> String;
}

#[allow(unused)]
pub trait Diagnose {
    fn diagnostic(&self, diag: serde_json::Value);
}

impl<T: Diagnosable> Diagnose for T {
    fn diagnostic(&self, data: serde_json::Value) {
        if let Some(hc_sender) = self.sender().clone() {
            match hc_sender.send(Diagnostic {
                label: Self::label(),
                data,
            }) {
                Ok(_) => (),
                Err(e) => log::error!("Error sending diagnostic over channel {e:?}"),
            };
        } else {
            log::warn!("tried to record diagnostic {data} where sender wasn't present");
        };
    }
}

pub type DiagnosticSender = Arc<mpsc::UnboundedSender<Diagnostic>>;
