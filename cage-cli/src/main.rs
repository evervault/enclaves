use clap::Parser;
use tokio::fs::File;
use tokio_util::codec::FramedRead;
use futures::stream::StreamExt;

mod docker;
use docker::enclave_builder;
use docker::parse::{Directive, Mode};

#[derive(Parser,Debug)]
#[clap(name = "build")]
struct BuildArgs {
    #[clap(short='f', long="file", default_value="Dockerfile")]
    dockerfile: String,
}

#[tokio::main]
async fn main() {
    // using this as it's a Dockerfile currently in the repo
    let build_args = BuildArgs{ dockerfile: "./nitro-cli-image.Dockerfile".to_string() };
    // read dockerfile
    let dockerfile_path = std::path::Path::new(build_args.dockerfile.as_str());
    if !dockerfile_path.exists() {
        eprintln!("{} does not exist", build_args.dockerfile);
        return;
    }

    let dockerfile = match File::open(dockerfile_path).await {
        Ok(dockerfile) => dockerfile,
        Err(e) => {
            eprintln!("Error accessing dockerfile - {:?}", e);
            return;
        }
    };

    let mut instruction_set = Vec::new();
    let mut last_cmd = None;
    let mut last_entrypoint = None;

    let mut dockerfile_reader = FramedRead::new(
        dockerfile,
        docker::parse::DockerfileDecoder::new()
    );

    let handle_emitted_instructions = |
        instruction_set: &mut Vec<Directive>,
        instruction: Directive,
        last_cmd: &mut Option<Directive>,
        last_entrypoint: &mut Option<Directive>
    | {
        if instruction.is_cmd() {
            *last_cmd = Some(instruction);
        } else if instruction.is_entrypoint() {
            *last_entrypoint = Some(instruction);
        } else if !instruction.is_expose() {
            instruction_set.push(instruction);
        }
    };

    while let Some(instruction) = dockerfile_reader.next().await {
        match instruction {
            Ok(directive) => handle_emitted_instructions(
                &mut instruction_set,
                directive,
                &mut last_cmd,
                &mut last_entrypoint
            ),
            Err(e) => eprintln!("Error parsing dockerfile — {:?}", e)
        }
    }

    if last_entrypoint.is_none() && last_cmd.is_none() {
        eprintln!("Invalid dockerfile — no entrypoint or CMD found");
        return;
    }

    // TODO: Add entrypoint as exec command to runit service
    let _entrypoint = docker::create_combined_docker_entrypoint(last_entrypoint, last_cmd);
    let new_entrypoint = Directive::new_entrypoint(Mode::Exec, vec!["runsvdir".to_string(), "/etc/service".to_string()]);
    instruction_set.push(new_entrypoint);
    instruction_set.iter().for_each(|instruction| {
        println!("{}", instruction)
    });

    // build enclave, and also output in current directory. Mainly here just to avoid "unused" warnings
    let user_context_path = "..";
    let user_dockerfile_path = "../runtime/Dockerfile";
    let _temp_output_dir = enclave_builder::build_enclave(user_dockerfile_path, user_context_path, true, false).unwrap();
}


