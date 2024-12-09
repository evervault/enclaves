use std::process::{Output, Stdio};

use log::info;
use serde_json::Value;
use thiserror::Error;
use tokio::process::Command;

use crate::configuration::get_enclave_run_config;

#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error("An error occurred - {0:?}")]
    CommandFailed(String),
    #[error("Json Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// trait Orchestration {
//     fn shutdown_all_enclaves() -> Result<Output, OrchestrationError>;
//     fn start_enclave() -> Result<(), OrchestrationError>;
//     fn run_command_capture_stdout(args: &[&str]) -> Result<String, OrchestrationError>;
// }

pub struct Orchestration;

impl Orchestration {
    pub async fn shutdown_all_enclaves() -> Result<Output, OrchestrationError> {
        Command::new("sh")
            .arg("-c")
            .arg("nitro-cli terminate-enclave --all")
            .output()
            .await
            .map_err(|e| OrchestrationError::Io(e))
    }

    pub async fn start_enclave() -> Result<(), OrchestrationError> {
        let run_config = get_enclave_run_config();

        info!("[HOST] Checking for running enclaves...");

        let running_enclaves =
            Self::run_command_capture_stdout(&["nitro-cli", "describe-enclaves"]).await?;
        let enclaves: Value = serde_json::from_str(&running_enclaves)?;
        let v = vec![];
        let enclaves_array = enclaves.as_array().unwrap_or(&v);
        if enclaves_array.len() > 0 {
            info!("There's an enclave already running on this host. Terminating it...");
            Self::shutdown_all_enclaves().await?;
            info!("Enclave terminated. Waiting 10s...");
            std::thread::sleep(std::time::Duration::from_secs(10));
        } else {
            info!("No enclaves currently running on this host.");
        }

        println!("Starting new enclave...");
        let mut run_command = vec![
            "nitro-cli",
            "run-enclave",
            "--cpu-count",
            &run_config.num_cpus,
            "--memory",
            &run_config.ram_size_mib,
            "--enclave-cid",
            "2021",
            "--eif-path",
            "enclave.eif",
        ];

        if run_config.debug_mode == "true" {
            println!("Debug mode enabled...");
            run_command.push("--debug-mode");
        } else {
            println!("Debug mode disabled...");
        }

        Self::run_command_capture_stdout(&run_command).await?;

        info!("Enclave started... Waiting 5 seconds for warmup.");
        std::thread::sleep(std::time::Duration::from_secs(10));

        if run_config.debug_mode == "true" {
            println!("Attaching headless console for running enclaves...");
            let running_enclaves =
                Self::run_command_capture_stdout(&["nitro-cli", "describe-enclaves"]).await?;
            let enclaves: Value = serde_json::from_str(&running_enclaves)?;
            let v = vec![];
            let enclaves_array = enclaves.as_array().unwrap_or(&v);
            for enclave in enclaves_array {
                let id = enclave["EnclaveID"].as_str().unwrap();
                Self::run_command_capture_stdout(&["nitro-cli", "console", "--enclave-id", id])
                    .await?;
            }
        }
        Ok(())
    }

    async fn run_command_capture_stdout(args: &[&str]) -> Result<String, OrchestrationError> {
        let output = Command::new(args[0])
            .args(&args[1..])
            .stderr(Stdio::inherit())
            .output()
            .await?;

        if !output.status.success() {
            return Err(OrchestrationError::CommandFailed(
                format!(
                    "Command {:?} failed with exit status: {}",
                    args, output.status
                )
                .into(),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
