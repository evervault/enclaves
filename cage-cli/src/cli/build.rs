use crate::docker::parse::{DecodeError, Directive, DockerfileDecoder, Mode};
use crate::docker::utils::verify_docker_is_running;
use crate::enclave;
use atty::Stream;
use clap::Parser;
use std::io::Write;
use std::path::Path;
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

    /// Save enclave file
    #[clap(long)]
    pub save: bool,
}

pub async fn run(build_args: BuildArgs) {
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
        log::error!("{} does not exist", build_args.dockerfile);
        return;
    }

    let dockerfile = match File::open(dockerfile_path).await {
        Ok(dockerfile) => dockerfile,
        Err(e) => {
            log::error!("Error accessing dockerfile - {:?}", e);
            return;
        }
    };

    let built_dockerfile = match process_dockerfile(dockerfile).await {
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
    let mut ev_user_dockerfile = std::fs::File::create(EV_USER_DOCKERFILE_PATH).unwrap();

    built_dockerfile.iter().for_each(|instruction| {
        writeln!(ev_user_dockerfile, "{}", instruction).unwrap();
    });
    log::info!("{} saved in current directory.", EV_USER_DOCKERFILE_PATH);

    // build enclave, and also output in current directory. Mainly here just to avoid "unused" warnings
    let user_context_path = ".";

    let command_config = enclave::CommandConfig::new(build_args.verbose);
    log::info!("Building docker image…");
    if let Err(e) =
        enclave::build_user_image(EV_USER_DOCKERFILE_PATH, user_context_path, &command_config)
    {
        log::error!("An error occurred while building the docker image. {}", e);
        return;
    }
    log::info!("Building enclave compatible image…");
    if let Err(e) = enclave::build_nitro_cli_image(&command_config) {
        log::error!("An error occurred while building the enclave image. {}", e);
        return;
    }
    log::info!("Converting docker image to EIF…");
    let enclave_filename: &str = "enclave.eif";
    let built_enclave = match enclave::run_conversion_to_enclave(&command_config, enclave_filename)
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

    if build_args.save {
        std::fs::copy(
            format!(
                "{}/{}",
                built_enclave.location().path().to_str().unwrap(),
                enclave_filename
            ),
            enclave_filename,
        )
        .unwrap();
        log::info!("{} saved in the current directory.", enclave_filename);
    }

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

    let remove_unwanted_directives = |directive: &Directive| -> bool {
        if directive.is_cmd() {
            last_cmd = Some(directive.clone());
            false
        } else if directive.is_entrypoint() {
            last_entrypoint = Some(directive.clone());
            false
        } else {
            !directive.is_expose()
        }
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
    use super::process_dockerfile;
    use crate::docker;
    use itertools::zip;

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
}
