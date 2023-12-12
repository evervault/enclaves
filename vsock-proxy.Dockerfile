FROM rust:1.74-slim-bookworm

ARG APP_NAME=vsock-proxy
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY crates/vsock-proxy vsock-proxy
COPY shared shared

RUN apt-get update && apt-get install -y build-essential libssl-dev perl

RUN cargo build --features enclave --release

# RUN cp target/release/${APP_NAME} /bin/mini-e3
CMD ["/app/target/release/mini-e3"]
