use std::process::Stdio;

use log::info;
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use crate::configuration::get_enclave_run_config;

#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error("An error occurred - {0:?}")]
    CommandFailed(String),
    #[error("Json Error — {0:?}")]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    VarError(#[from] std::env::VarError),
}

static EMPTY_VEC: Vec<Value> = Vec::new();
const ENCLAVE_CID: &str = "2021";
const EIF_PATH: &str = "enclave.eif";
const NITRO_CLI: &str = "nitro-cli";

enum NitroCommand {
    TerminateEnclave,
    DescribeEnclaves,
    RunEnclave,
    Console,
}

impl NitroCommand {
    pub fn as_str(&self) -> &str {
        match self {
            NitroCommand::TerminateEnclave => "terminate-enclave",
            NitroCommand::DescribeEnclaves => "describe-enclaves",
            NitroCommand::RunEnclave => "run-enclave",
            NitroCommand::Console => "console",
        }
    }
}

pub struct Orchestration;

impl Orchestration {
    pub async fn shutdown_all_enclaves() -> Result<String, OrchestrationError> {
        let command = vec![
            "sh",
            "-c",
            NITRO_CLI,
            NitroCommand::TerminateEnclave.as_str(),
            "--all",
        ];
        Self::run_command_capture_stdout(&command).await
    }

    pub async fn start_enclave() -> Result<(), OrchestrationError> {
        let run_config = get_enclave_run_config()?;

        info!("[HOST] Checking for running enclaves...");

        let running_enclaves =
            Self::run_command_capture_stdout(&[NITRO_CLI, NitroCommand::DescribeEnclaves.as_str()])
                .await?;
        let enclaves: Value = serde_json::from_str(&running_enclaves)?;
        let enclaves_array = enclaves.as_array().unwrap_or(&EMPTY_VEC);
        if !enclaves_array.is_empty() {
            info!("There's an enclave already running on this host. Terminating it...");
            Self::shutdown_all_enclaves().await?;
            info!("Enclave terminated. Waiting 10s...");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        } else {
            info!("No enclaves currently running on this host.");
        }

        info!("Starting new enclave...");
        let mut run_command = vec![
            NITRO_CLI,
            NitroCommand::RunEnclave.as_str(),
            "--cpu-count",
            &run_config.num_cpus,
            "--memory",
            &run_config.ram_size_mib,
            "--enclave-cid",
            ENCLAVE_CID,
            "--eif-path",
            EIF_PATH,
        ];

        if run_config.debug_mode == "true" {
            info!("Debug mode enabled...");
            run_command.push("--debug-mode");
        } else {
            info!("Debug mode disabled...");
        }

        Self::run_command_capture_stdout(&run_command).await?;

        info!("Enclave started... Waiting 5 seconds for warmup.");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if run_config.debug_mode == "true" {
            Self::send_debug_logs_to_stdout().await?;
        }
        Ok(())
    }

    async fn send_debug_logs_to_stdout() -> Result<(), OrchestrationError> {
        info!("Attaching headless console for running enclaves...");
        let running_enclaves =
            Self::run_command_capture_stdout(&[NITRO_CLI, NitroCommand::DescribeEnclaves.as_str()])
                .await?;
        let enclaves: Value = serde_json::from_str(&running_enclaves)?;
        let enclaves_array = enclaves.as_array().unwrap_or(&EMPTY_VEC).clone();
        for enclave in enclaves_array {
            if let Some(id) = enclave["EnclaveID"].as_str() {
                let mut child = Command::new(NITRO_CLI)
                    .args([NitroCommand::Console.as_str(), "--enclave-id", id])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;

                if let Some(stdout) = child.stdout.take() {
                    tokio::spawn(async move {
                        let mut lines = BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            info!("[ENCLAVE]: {}", line);
                        }
                    });
                }
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
            return Err(OrchestrationError::CommandFailed(format!(
                "Command {:?} failed with exit status: {}",
                args, output.status
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
