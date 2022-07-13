use crate::docker::parse::{DecodeError, Directive, DockerfileDecoder, Mode};
use crate::docker::utils::verify_docker_is_running;
use crate::enclave;
use atty::Stream;
use clap::Parser;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncRead;

const EV_USER_DOCKERFILE_PATH: &str = "ev-user.Dockerfile";
const USER_ENTRYPOINT_SERVICE_PATH: &str = "/etc/service/user-entrypoint";

/// Build a Cage from a Dockerfile
#[derive(Parser, Debug)]
#[clap(name = "build", about)]
pub struct BuildArgs {
    /// The dockerfile to convert into a cage
    #[clap(short = 'f', long = "file", default_value = "Dockerfile")]
    dockerfile: String,

    /// Enable verbose output
    #[clap(short, long, from_global)]
    pub verbose: bool,

    /// Enable JSON output
    #[clap(long, from_global)]
    pub json: bool,

    /// Path to directory where the processed docker image and enclave will be saved
    #[clap(short = 'o', long = "output")]
    pub output_dir: Option<String>,
}

pub async fn run(build_args: BuildArgs) {
    // temporary directory must remain in scope for the whole
    // function so it isn't deleted until all the builds are finished.
    let (output_dir_path, _tmp_output_dir) =
        if let Some(output_dir) = build_args.output_dir.as_ref() {
            let path = Path::new(output_dir);
            if !path.exists() {
                log::error!("The directory {} does not exist.", output_dir);
                return;
            }
            match path.canonicalize() {
                Ok(absolute_path) => (absolute_path.as_path().to_str().unwrap().to_string(), None),
                Err(err) => {
                    log::error!("Failed to get absolute path of directory, error: {:?}", err);
                    return;
                }
            }
        } else {
            match TempDir::new() {
                Ok(tmp_dir) => (tmp_dir.path().to_str().unwrap().to_string(), Some(tmp_dir)),
                Err(err) => {
                    log::error!(
                    "Failed to create temporary directory for storing generated files, error: {:?}",
                    err
                );
                    return;
                }
            }
        };

    match verify_docker_is_running() {
        Ok(false) => {
            log::error!("Failed to communicate with docker. Please verify that docker is running and accessible.");
            return;
        }
        Err(e) => {
            log::error!(
                "Process failed when checking if docker was running. Please try again. {:?}",
                e
            );
            return;
        }
        _ => {}
    }

    // read dockerfile
    let dockerfile_path = Path::new(build_args.dockerfile.as_str());
    if !dockerfile_path.exists() {
        log::error!(
            "{} does not exist. You can specify the path to your dockerfile using the -f flag.",
            build_args.dockerfile
        );
        return;
    }

    let dockerfile = match File::open(dockerfile_path).await {
        Ok(dockerfile) => dockerfile,
        Err(e) => {
            log::error!("Error accessing dockerfile - {:?}", e);
            return;
        }
    };

    let processed_dockerfile = match process_dockerfile(dockerfile).await {
        Ok(directives) => directives,
        Err(e) => {
            log::error!(
                "An error occurred while processing your dockerfile - {:?}",
                e
            );
            return;
        }
    };

    // write new dockerfile to fs
    let ev_user_dockerfile_path = format!("{}/{}", output_dir_path, EV_USER_DOCKERFILE_PATH);
    let mut ev_user_dockerfile = std::fs::File::create(&ev_user_dockerfile_path).unwrap();

    processed_dockerfile.iter().for_each(|instruction| {
        writeln!(ev_user_dockerfile, "{}", instruction).unwrap();
    });

    log::debug!("Processed dockerfile saved at {}.", ev_user_dockerfile_path);

    let command_config = enclave::CommandConfig::new(build_args.verbose);
    log::info!("Building docker image…");
    if let Err(e) = enclave::build_user_image(&ev_user_dockerfile_path, ".", &command_config) {
        log::error!("An error occurred while building the docker image. {}", e);
        return;
    }

    log::debug!("Building Nitro CLI image…");
    if let Err(e) = enclave::build_nitro_cli_image(&command_config, &output_dir_path) {
        log::debug!("An error occurred while building the enclave image. {}", e);
        return;
    }

    log::info!("Converting docker image to EIF…");
    let built_enclave = match enclave::run_conversion_to_enclave(&command_config, &output_dir_path)
    {
        Ok(built_enclave) => built_enclave,
        Err(e) => {
            log::error!(
                "An error occurred while converting your docker image to an enclave. {:?}",
                e
            );
            return;
        }
    };

    // Write enclave measures to stdout
    let success_msg = serde_json::json!({
        "status": "success",
        "message": "EIF built successfully",
        "enclaveMeasurements": built_enclave.measurements()
    });

    if atty::is(Stream::Stdout) {
        // nicely format the JSON when printing to a TTY
        println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
    } else {
        println!("{}", serde_json::to_string(&success_msg).unwrap());
    }
}

async fn process_dockerfile<R: AsyncRead + std::marker::Unpin>(
    dockerfile_src: R,
) -> Result<Vec<Directive>, DecodeError> {
    // Decode dockerfile from file
    let instruction_set = DockerfileDecoder::decode_dockerfile_from_src(dockerfile_src).await?;

    // Filter out unwanted directives
    let mut last_cmd = None;
    let mut last_entrypoint = None;
    let mut exposed_port: Option<u16> = None;

    let remove_unwanted_directives = |directive: &Directive| -> bool {
        if directive.is_cmd() {
            last_cmd = Some(directive.clone());
        } else if directive.is_entrypoint() {
            last_entrypoint = Some(directive.clone());
        } else if let Directive::Expose { port } = directive {
            exposed_port = *port;
        } else {
            return true;
        }
        false
    };

    let cleaned_instructions: Vec<Directive> = instruction_set
        .into_iter()
        .filter(remove_unwanted_directives)
        .collect();

    let (user_service_builder, user_service_location) =
        crate::docker::utils::create_combined_docker_entrypoint(last_entrypoint, last_cmd).map(
            |entrypoint| {
                let user_service_runner = format!("{USER_ENTRYPOINT_SERVICE_PATH}/run");
                let user_service_builder_script = crate::docker::utils::write_command_to_script(
                    entrypoint.as_str(),
                    user_service_runner.as_str(),
                );
                (
                    Directive::new_run(user_service_builder_script),
                    user_service_runner,
                )
            },
        )?;

    if let Some(port) = exposed_port {
        log::debug!("Customer service will listen on port: {}", port);
    }

    let injected_directives = vec![
        // install dependencies
        Directive::new_run("apk update ; apk add runit ; rm -rf /var/cache/apk/*"),
        // create user service directory
        Directive::new_run(format!("mkdir {USER_ENTRYPOINT_SERVICE_PATH}")),
        // add user service runner
        user_service_builder,
        // give execute permissions on runner
        Directive::new_run(format!("chmod +x {user_service_location}")),
        // add entrypoint which starts the runit services
        Directive::new_entrypoint(
            Mode::Exec,
            vec!["runsvdir".to_string(), "/etc/service".to_string()],
        ),
    ];

    // add custom directives to end of dockerfile
    Ok([cleaned_instructions, injected_directives].concat())
}

#[cfg(test)]
mod test {
    use super::{process_dockerfile, run, BuildArgs};
    use crate::docker;
    use crate::enclave;
    use itertools::zip;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_process_dockerfile() {
        let sample_dockerfile_contents = r#"FROM alpine

RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"

ENTRYPOINT ["sh", "/hello-script"]"#;
        let mut readable_contents = sample_dockerfile_contents.as_bytes();

        let processed_file = process_dockerfile(&mut readable_contents).await;
        assert_eq!(processed_file.is_ok(), true);
        let processed_file = processed_file.unwrap();

        let expected_output_contents = r#"FROM alpine
RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
RUN apk update ; apk add runit ; rm -rf /var/cache/apk/*
RUN mkdir /etc/service/user-entrypoint
RUN /bin/sh -c "echo -e '"'#!/bin/sh\nsh /hello-script\n'"' > /etc/service/user-entrypoint/run"
RUN chmod +x /etc/service/user-entrypoint/run
ENTRYPOINT ["runsvdir", "/etc/service"]
"#;
        let expected_directives = docker::parse::DockerfileDecoder::decode_dockerfile_from_src(
            expected_output_contents.as_bytes(),
        )
        .await
        .unwrap();

        assert_eq!(expected_directives.len(), processed_file.len());
        for (expected_directive, processed_directive) in
            zip(expected_directives.iter(), processed_file.iter())
        {
            assert_eq!(
                expected_directive.to_string(),
                processed_directive.to_string()
            );
        }
    }

    // Commented out until self-hosted actions runner with Docker is up and running.

    // #[tokio::test]
    // async fn test_choose_output_dir() {
    //     let output_dir = TempDir::new().unwrap();

    //     let build_args = BuildArgs {
    //         dockerfile: "./sample-user.Dockerfile".to_string(),
    //         verbose: false,
    //         json: false,
    //         output_dir: Some(output_dir.path().to_str().unwrap().to_string()),
    //     };

    //     println!("output_dir: {}", output_dir.path().to_str().unwrap().to_string());

    //     run(build_args).await;

    //     let paths = std::fs::read_dir(output_dir.path().to_str().unwrap().to_string()).unwrap();

    //     for path in paths {
    //         println!("Name: {}", path.unwrap().path().display())
    //     }

    //     assert_eq!(output_dir.path().join(super::EV_USER_DOCKERFILE_PATH).exists(), true);
    //     assert_eq!(output_dir.path().join(enclave::NITRO_CLI_IMAGE_FILENAME).exists(), true);
    //     assert_eq!(output_dir.path().join(enclave::ENCLAVE_FILENAME).exists(), true);
    // }
}
