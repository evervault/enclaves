use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

pub type DiagnosticSender = Arc<mpsc::UnboundedSender<Diagnostic>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Diagnostic {
    pub label: String,
    pub data: serde_json::Value,
}
