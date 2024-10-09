use shared::server::diagnostic::{Diagnostic, DiagnosticSender};

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
        if let Some(diag_sender) = self.sender().clone() {
            match diag_sender.send(Diagnostic {
                label: Self::label(),
                data,
            }) {
                Ok(_) => (),
                Err(e) => log::error!("Error sending diagnostic over channel {e:?}"),
            };
        } else {
            log::warn!(
                "tried to record diagnostic in {} where sender wasn't present",
                Self::label()
            );
        };
    }
}
