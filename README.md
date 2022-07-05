# Cages

Run code on TEEs (Trusted Execution Environments)

## Ports

If you're runnning the project locally the services are running on the following ports

- Control Plane
    - HTTP server: 3030
    - TCP/Mock Vsock server: 8888
- Data Plane
    - DNS listener: 5300
    - TCP/Mock Vsock server: 7777
- Customer Service : 8008

## Feature flags

The data plane and control plane can be compiled and run without network egress form the enclave

```
cargo run --features network_egress 
```

## Query Local DNS Server

The enclave DNS forwarder is listening on 5300 locally. To test lookup from data plane -> control plane -> remote DNS server use the following command:

```
dig evervault.com -p 5300 @127.0.0.1
```


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
