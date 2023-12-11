FROM rust:1.74-bookworm

COPY mini-e3/Cargo.toml /Cargo.toml

COPY mini-e3/src /src
COPY shared .
RUN cargo build --features enclave

ENTRYPOINT [ "./target/release/mini-e3" ]
