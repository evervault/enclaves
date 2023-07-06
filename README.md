<a href="https://evervault.com/cages"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Evervault Cages

Evervault Cages are the easiest way to build, deploy and scale Secure Enclaves.

Evervault Cages allow developers to easily deploy Docker containers in a Secure Enclave, powered by AWS Nitro Enclaves. Cages offer easy deployment, invocation and attestation of Secure Enclaves without the engineering overhead.

This repo consists of two components: the runtime which is run _inside_ the Secure Enclave (the "data plane") and the code used for proxying network traffic and initializing the enclave (the "control plane").

## Notice on Open Source Status of this project

The Evervault Cages product is open source with the aim of providing transparency to users — this is vital given that our process runs in the enclave, and is accounted for in the attestation.

The current state of this project does not allow for self-hosting. We plan on addressing this by abstracting away the Evervault-specific elements of the Cages product.

## Steps to get Cages running in local dev (macOSarm64)
Add a `.cargo` directory to the project root, and create a `.cargo/config.toml` containing the following:

```toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
```

If you're using vscode you may want to append a check target to your workspace settings

`.vscode/settings.json`
```sh
{
	"rust-analyzer.check.targets": "x86_64-unknown-linux-musl"
}
```

Install the required packages for cross compilation:
```sh
brew tap SergioBenitez/osxct
brew install FiloSottile/musl-cross/musl-cross # don't be alarmed if this takes a while https://github.com/FiloSottile/homebrew-musl-cross/issues/15
rustup target add x86_64-unknown-linux-musl
ln -s $(which x86_64-linux-musl-gcc) /usr/local/bin/musl-gcc
```

Generate a cert and key for the data-plane:
```sh
# install mkcert as a trusted CA
mkcert -install

mkcert data-plane.localhost
```

Generate test certs:
```sh
./e2e-tests/mtls-testing-certs/ca/generate-certs.sh
```

Generate certs for TLS in the mock API:
```sh
mkdir e2e-tests/testing-certs && mkcd e2e-tests/testing-certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./testing.key -out testing.crt
```

Source `export-dev-env-vars.sh` to set certs as environment variables:
```sh
source ./scripts/export-dev-env-vars.sh
```

Compile:
```sh
cargo build --release --target x86_64-unknown-linux-musl --features network_egress
```

Compile the mock crypto crate:
```sh
pushd e2e-tests/mock-crypto && cargo build --release --target x86_64-unknown-linux-musl && popd
```

Build and run docker containers:
```sh
docker compose build
docker compose up
```

Test it out:
```sh
curl https://cage.localhost:443/encrypt -k -H 'api-key: placeholder' --data '{"hello": "world"}' -H "Content-Type: application/json"
```

## Feature flags

By default, the data plane and control plane will be compiled and run without network egress from the enclave.
```sh
cargo run
```

The data plane and control plane can be compiled and run with network egress support using the `network_egress` feature flag.
```sh
cargo run --features network_egress
```

To build with the `enclave` feature flag, you will have to specify the target:
```sh
sudo cargo clippy --features enclave --target x86_64-unknown-linux-musl
```

You may need to install `musl-cross` (Note: this will take a while, ~30+ minutes):
```sh
brew install FiloSottile/musl-cross/musl-cross
```

You will also need the `x86_64-unknown-linux-musl` target:
```sh
rustup target add x86_64-unknown-linux-musl
```

## Query Local DNS Server

The enclave DNS forwarder is listening on 53. To test lookup from data plane -> control plane -> remote DNS server use the following command:
```sh
dig evervault.com @127.0.0.1
```

## Run end-to-end tests
```sh
sh e2e-tests/run.sh
```

The mock crypto API depends on a (currently private) Rust crate. We plan on making this crate available in future.
Until then, the project will be able to build and run the E2E tests in CI.
