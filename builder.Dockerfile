FROM clux/muslrust:1.64.0

COPY data-plane/Cargo.toml /Cargo.toml
COPY data-plane/Cargo.lock /Cargo.lock
RUN rustup component add clippy

COPY data-plane/src /src
RUN cargo build --features enclave,network_egress --target x86_64-unknown-linux-musl

ENTRYPOINT [ "/bin/sh", "-c" ]
