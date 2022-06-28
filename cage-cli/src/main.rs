use bytes::{Buf, BytesMut};
use clap::Parser;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::codec::Decoder;
use crate::docker::parse::Instruction;

mod docker;

#[derive(Parser,Debug)]
#[clap(name = "build")]
struct BuildArgs {
    #[clap(short='f', long="file", default_value="Dockerfile")]
    dockerfile: String,
}

#[tokio::main]
async fn main() {
    let build_args = BuildArgs::parse();
    // read dockerfile
    let dockerfile_path = std::path::Path::new(build_args.dockerfile.as_str());
    if !dockerfile_path.exists() {
        eprintln!("{} does not exist", build_args.dockerfile);
        return;
    }

    let mut dockerfile = match File::open(dockerfile_path).await {
        Ok(dockerfile) => dockerfile,
        Err(e) => {
            eprintln!("Error accessing dockerfile - {:?}", e);
            return;
        }
    };

    let mut buf = BytesMut::with_capacity(1024);
    let mut eof = false;
    let mut dockerfile_decoder = docker::parse::DockerfileDecoder::new();
    let mut instruction_set = Vec::new();
    let mut last_cmd = None;
    let mut last_entrypoint = None;

    let handle_emitted_instructions = |
        instruction_set: &mut Vec<Instruction>,
        instruction: Instruction,
        last_cmd: &mut Option<Instruction>,
        last_entrypoint: &mut Option<Instruction>
    | {
        if instruction.is_cmd() {
            *last_cmd = Some(instruction);
        } else if instruction.is_entrypoint() {
            *last_entrypoint = Some(instruction);
        } else if !instruction.is_expose() {
            instruction_set.push(instruction);
        }
    };

    'outer: loop {
        if !eof {
            match dockerfile.read_buf(&mut buf).await {
                Ok(consumed) if consumed == 0 => {
                    eof = true;
                },
                Err(e) => {
                    eprintln!("Error reading dockerfile - {:?}", e);
                    return;
                },
                _ => {}
            };
        }
        'inner: loop {
            if !buf.has_remaining() && eof {
                if let Some(final_instruction) = dockerfile_decoder.flush() {
                    handle_emitted_instructions(&mut instruction_set, final_instruction, &mut last_cmd, &mut last_entrypoint);
                }
                break 'outer;
            }
            match dockerfile_decoder.decode(&mut buf) {
                Ok(Some(instruction)) => {
                    handle_emitted_instructions(&mut instruction_set, instruction, &mut last_cmd, &mut last_entrypoint);
                    continue;
                },
                Ok(None) if dockerfile_decoder.eof() && !buf.has_remaining() => break 'outer,
                Ok(None) => break 'inner,
                Err(e) => {
                    eprintln!("Error parsing dockerfile - {:?}", e);
                    break 'outer;
                }
            };
        }
    }

    instruction_set.iter().for_each(|instruction| {
        println!("{}", instruction)
    });
}
