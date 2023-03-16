<a href="https://evervault.com/cages"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Evervault Cages

Evervault Cages are the easiest way to build, deploy and scale Secure Enclaves.

Evervault Cages allow developers to easily deploy Docker containers in a Secure Enclave, powered by AWS Nitro Enclaves. Cages offer easy deployment, invocation and attestation of Secure Enclaves without the engineering overhead.

This repo consists of two components: the runtime which is run _inside_ the Secure Enclave (the "data plane") and the code used for proxying network traffic and initializing the enclave (the "control plane").

## Notice on Open Source Status of this project

The Evervault Cages product is open source with the aim of providing transparency to users — this is vital given that our process runs in the enclave, and is accounted for in the attestation.

The current state of this project does not allow for self-hosting. We plan on addressing this by abstracting away the Evervault-specific elements of the Cages product.

## Steps to get Cages running with a test customer process

```sh
cargo build --release --target x86_64-unknown-linux-musl --features network_egress
./e2e-tests/mtls-testing-certs/ca/generate-certs.sh
docker compose build
docker compose up
```

## Test it out

```sh
curl https://cage.localhost:443/encrypt -k -H 'api-key: <API_KEY>' --data '{"hello": "world"}' -H "Content-Type: application/json"
```

## Feature flags

By default, the data plane and control plane will be compiled and run without network egress from the enclave.

```
cargo run
```

The data plane and control plane can be compiled and run with network egress support using the `network_egress` feature flag.

```
cargo run --features network_egress
```

To build with the `enclave` feature flag, you will have to specify the target:

```
sudo cargo clippy --features enclave --target x86_64-unknown-linux-musl
```

You may need to install `musl-cross` (Note: this will take a while, ~30+ minutes):

```bash
brew install FiloSottile/musl-cross/musl-cross
```

You will also need the `x86_64-unknown-linux-musl` target:

```bash
rustup target add x86_64-unknown-linux-musl
```

## Query Local DNS Server

The enclave DNS forwarder is listening on 53. To test lookup from data plane -> control plane -> remote DNS server use the following command:

```
dig evervault.com @127.0.0.1
```

## Temp Running Instructions

Generate certs for TLS in the mock API

```
mkdir e2e-tests/testing-certs && cd e2e-tests/testing-certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./testing.key -out testing.crt
```

Run end-to-end tests

```
sh e2e-tests/run.sh
```

The mock crypto API depends on a (currently private) Rust crate. We plan on making this crate available in future.
Until then, the project will be able to build and run the E2E tests in CI.

## Runtime

The [runtime](./runtime) directory contains a Dockerfile for building an image which runs our data plane alongside a sample user-entrypoint script.

This currently requires the data plane executable to be compiled locally, with an `x86_64` architecture. In future the Dockerfile will download this executable instead.

<details>
  <summary>Steps for Cross Compilation on MacOS with Arm</summary>

Install the required packages for cross compilation:

```sh
brew tap SergioBenitez/osxct
brew install FiloSottile/musl-cross/musl-cross #don't be alarmed if this takes a while https://github.com/FiloSottile/homebrew-musl-cross/issues/15
rustup target add x86_64-unknown-linux-musl
ln -s $(which x86_64-linux-musl-gcc) /usr/local/bin/musl-gcc
```

Add a `.cargo` directory to the project root, and create a `.cargo/config.toml` containing the following:

```toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
```

</details>

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Now the Dockerfile can be built and run (from the project root)

```
docker build --platform linux/amd64 -t data-plane -f runtime/Dockerfile .
```

```
docker run -it --rm --name data-plane-container data-plane
```
