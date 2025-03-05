<a href="https://evervault.com/primitives/enclaves"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Evervault Enclaves

Evervault Enclaves are the easiest way to build, deploy and scale Secure Enclaves.

Evervault Enclaves allow developers to easily deploy Docker containers in a Secure Enclave, powered by AWS Nitro Enclaves. Enclaves offer easy deployment, invocation and attestation of Secure Enclaves without the engineering overhead.

This repo consists of two components: the runtime which is run _inside_ the Secure Enclave (the "data plane") and the code used for proxying network traffic and initializing the enclave (the "control plane").

## Notice on Open Source Status of this project

The Evervault Enclaves product is open source with the aim of providing transparency to users — this is vital given that our process runs in the enclave, and is accounted for in the attestation.

The current state of this project does not allow for self-hosting. We plan on addressing this by abstracting away the Evervault-specific elements of the Enclaves product.

## Steps to get Enclaves running in local dev (macOSarm64)

If you're using vscode you may want to append a check target to your workspace settings

`.vscode/settings.json`
```sh
{
	"rust-analyzer.check.targets": "x86_64-unknown-linux-musl"
}
```

The crates can then be cross compiled using zigbuild. To install zigbuild, first [install ziglang](https://ziglang.org/learn/getting-started/#installing-zig).

Once ziglang is installed, you can install zigbuild as a cargo plugin:

```sh
cargo install --locked cargo-zigbuild
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

Generate the Root and Intermediate CA for cert provisioning in tests:
```sh
sh ./e2e-tests/generate-sample-ca.sh
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
cargo zigbuild --release --target x86_64-unknown-linux-musl --features network_egress
```

Compile the mock crypto crate:
```sh
pushd e2e-tests/mock-crypto && cargo zigbuild --release --target x86_64-unknown-linux-musl && popd
```

Build and run docker containers:
```sh
docker compose build
docker compose up
```

Test it out:
```sh
curl https://enclave.localhost:443/encrypt -k -H 'api-key: placeholder' --data '{"hello": "world"}' -H "Content-Type: application/json"
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
