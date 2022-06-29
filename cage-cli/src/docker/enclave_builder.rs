use std::process::{Command, Stdio};
use tempdir::TempDir;

const NITRO_CLI_DOCKERFILE_PATH: &str = "./nitro-cli-image.Dockerfile";
const IN_CONTAINER_VOLUME_DIR: &str = "/output";
pub const ENCLAVE_FILENAME: &str = "enclave.eif";
const EV_USER_IMAGE_NAME: &str = "ev-user-image";
const NITRO_CLI_IMAGE_NAME: &str = "nitro-cli-image";

struct CommandConfig {
    verbose: bool, 
    architecture: &'static str,
}

impl CommandConfig {
    pub fn extra_build_args(&self) -> Vec<&str> {
        match self.architecture {
            "aarch64" | "arm" => vec!["--platform", "linux/amd64"],
            _ => vec![]
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

fn build_user_image(user_dockerfile_path: &str, user_context_path: &str, command_config: &CommandConfig) -> Result<(), String> {
    println!("Building user image...");
    let build_image_args = [
        vec!["build", "-f", user_dockerfile_path, "-t", EV_USER_IMAGE_NAME],
        command_config.extra_build_args(),
        vec![user_context_path]
    ].concat();

    let build_image_status = Command::new("docker")
        .args(build_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status().expect("Failed to run docker command.");
    
    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build user image.".to_string())
    }
}

fn build_nitro_cli_image(command_config: &CommandConfig) -> Result<(), String> {
    println!("Building Nitro CLI image...");
    let temp_context_dir = TempDir::new("temp-context").unwrap();

    let build_nitro_cli_image_args = [
        vec!["build", "-f", NITRO_CLI_DOCKERFILE_PATH, "-t", NITRO_CLI_IMAGE_NAME],
        command_config.extra_build_args(),
        vec![temp_context_dir.path().to_str().unwrap()]
    ].concat();

    let build_image_status = Command::new("docker")
        .args(build_nitro_cli_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status().expect("Failed to run docker command for building Nitro CLI image.");
    
    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build Nitro CLI image.".to_string())
    }
}

fn run_conversion_to_enclave(command_config: &CommandConfig) -> Result<TempDir, String> {
    let output_dir = TempDir::new("nitro-cli-output").unwrap();
    
    println!("Converting user image to enclave...");
    let run_conversion_status = Command::new("docker")
        .args(vec![
            "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", format!("{}:{}", output_dir.path().to_str().unwrap(), IN_CONTAINER_VOLUME_DIR).as_str(),
            NITRO_CLI_IMAGE_NAME,
            "--output-file", &format!("{}/{}", IN_CONTAINER_VOLUME_DIR, ENCLAVE_FILENAME),
            "--docker-uri", EV_USER_IMAGE_NAME, 
        ])
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()
        .expect("Failed to run Nitro CLI image");
    

    if run_conversion_status.success() {
        Ok(output_dir)
    } else {
        Err("Failed to Nitro CLI image.".to_string())
    }
}

pub fn build_enclave(user_dockerfile_path: &str, user_context_path: &str, save_locally: bool, verbose: bool) -> Result<TempDir, String> {
    let architecture = std::env::consts::ARCH;
    let command_config = CommandConfig {
        verbose,
        architecture
    };

    build_user_image(user_dockerfile_path, user_context_path, &command_config)?;
    build_nitro_cli_image(&command_config)?;
    let output_dir = run_conversion_to_enclave(&command_config)?;

    if save_locally {
        std::fs::copy(
            format!("{}/{}", output_dir.path().to_str().unwrap(), ENCLAVE_FILENAME),
            ENCLAVE_FILENAME
        ).unwrap();
        println!("{} saved in the current directory.", ENCLAVE_FILENAME);
    }

    Ok(output_dir)
}

#[cfg(test)]
mod tests {
    use crate::docker::enclave_builder::{build_enclave, ENCLAVE_FILENAME};

    #[test]
    fn test_build_runtime() -> Result<(), String> {
        let user_context_path = "..";
        let user_dockerfile_path = "../runtime/Dockerfile";

        let temp_output_dir = build_enclave(user_dockerfile_path, user_context_path, false, false)?;
        // temporary directory containing the enclave.eif file is returned
        assert_eq!(temp_output_dir.path().join(ENCLAVE_FILENAME).exists(), true);
        Ok(())
    }
}
