# Cages

Run code on TEEs (Trusted Execution Environments)

## Temp Running Instructions

Run tests

```
sh tests/run.sh
```

## Runtime

The [runtime](./runtime) directory contains a Dockerfile for building an image which runs our data-plane alongside a sample user-entrypoint script.

This currently requires the data-plane executable to be compiled locally, with an `x86_64` architecture. In future the Dockerfile will download this executable instead. For M1 Macs, use the [guide](https://www.notion.so/evervault/Compiling-Rust-executable-for-linux-x86_64-on-M1-Mac-b31d2039decb49a1a006caf7bd930ca6) in Notion, and compile.

```bash
cd data-plane &&\
cargo build --release --target x86_64-unknown-linux-musl &&\
cd ..
```

Now the dockerfile can be built and run (from the project root)

```
docker build --platform linux/amd64 -t data-plane -f runtime/Dockerfile .
```

```
docker run -it --rm --name data-plane-container data-plane
```