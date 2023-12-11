FROM rust:1.74-slim-bookworm

ARG APP_NAME=mini-e3
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY mini-e3 mini-e3
COPY shared shared

RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev perl libssl3

RUN cargo build --features enclave --release

# RUN cp target/release/${APP_NAME} /bin/mini-e3
CMD ["/app/target/release/mini-e3"]
