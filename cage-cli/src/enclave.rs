use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use tempfile::TempDir;

const NITRO_CLI_DOCKERFILE_PATH: &str = "./nitro-cli-image.Dockerfile";
const IN_CONTAINER_VOLUME_DIR: &str = "/output";
const EV_USER_IMAGE_NAME: &str = "ev-user-image";
const NITRO_CLI_IMAGE_NAME: &str = "nitro-cli-image";

pub struct CommandConfig {
    verbose: bool,
    architecture: &'static str,
}

impl CommandConfig {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            architecture: std::env::consts::ARCH,
        }
    }

    pub fn extra_build_args(&self) -> Vec<&str> {
        match self.architecture {
            "aarch64" | "arm" => vec!["--platform", "linux/amd64"],
            _ => vec![],
        }
    }

    pub fn output_setting(&self) -> Stdio {
        if self.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }
}

pub fn build_user_image(
    user_dockerfile_path: &str,
    user_context_path: &str,
    command_config: &CommandConfig,
) -> Result<(), String> {
    let build_image_args = [
        vec![
            "build",
            "-f",
            user_dockerfile_path,
            "-t",
            EV_USER_IMAGE_NAME,
        ],
        command_config.extra_build_args(),
        vec![user_context_path],
    ]
    .concat();

    let build_image_status = Command::new("docker")
        .args(build_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()
        .expect("Failed to run docker command.");

    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build user image.".to_string())
    }
}

pub fn build_nitro_cli_image(command_config: &CommandConfig) -> Result<(), String> {
    let temp_context_dir = TempDir::new().unwrap();

    let build_nitro_cli_image_args = [
        vec![
            "build",
            "-f",
            NITRO_CLI_DOCKERFILE_PATH,
            "-t",
            NITRO_CLI_IMAGE_NAME,
        ],
        command_config.extra_build_args(),
        vec![temp_context_dir.path().to_str().unwrap()],
    ]
    .concat();

    let build_image_status = Command::new("docker")
        .args(build_nitro_cli_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()
        .expect("Failed to run docker command for building Nitro CLI image.");

    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build Nitro CLI image.".to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EIFMeasurements {
    #[serde(rename = "HashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "PCR0")]
    pcr0: String,
    #[serde(rename = "PCR1")]
    pcr1: String,
    #[serde(rename = "PCR2")]
    pcr2: String,
    #[serde(rename = "PCR8")]
    pcr8: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnclaveBuildOutput {
    measurements: EIFMeasurements,
}

#[derive(Debug)]
pub struct BuiltEnclave {
    measurements: EIFMeasurements,
    location: TempDir,
}

impl BuiltEnclave {
    pub fn measurements(&self) -> &EIFMeasurements {
        &self.measurements
    }

    pub fn location(&self) -> &TempDir {
        &self.location
    }
}

pub fn run_conversion_to_enclave(
    command_config: &CommandConfig,
    enclave_filename: &str,
) -> Result<BuiltEnclave, String> {
    let output_dir = TempDir::new().unwrap();
    let run_conversion_status = Command::new("docker")
        .args(vec![
            "run",
            "--rm",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            format!(
                "{}:{}",
                output_dir.path().to_str().unwrap(),
                IN_CONTAINER_VOLUME_DIR
            )
            .as_str(),
            NITRO_CLI_IMAGE_NAME,
            "--output-file",
            &format!("{}/{}", IN_CONTAINER_VOLUME_DIR, enclave_filename),
            "--docker-uri",
            EV_USER_IMAGE_NAME,
        ])
        .stdout(Stdio::piped()) // Write stdout to a buffer so we can parse the EIF meaasures
        .stderr(command_config.output_setting())
        .output()
        .expect("Failed to run Nitro CLI image");

    if run_conversion_status.status.success() {
        let build_output: EnclaveBuildOutput =
            serde_json::from_slice(run_conversion_status.stdout.as_slice()).unwrap();
        Ok(BuiltEnclave {
            measurements: build_output.measurements,
            location: output_dir,
        })
    } else {
        Err("Failed to Nitro CLI image.".to_string())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::docker::enclave_builder::{build_enclave, ENCLAVE_FILENAME};
//
//     #[test]
//     fn test_build_runtime() -> Result<(), String> {
//         let user_context_path = "..";
//         let user_dockerfile_path = "../runtime/Dockerfile";
//
//         let temp_output_dir = build_enclave(user_dockerfile_path, user_context_path, false, false)?;
//         // temporary directory containing the enclave.eif file is returned
//         assert_eq!(temp_output_dir.path().join(ENCLAVE_FILENAME).exists(), true);
//         Ok(())
//     }
// }
