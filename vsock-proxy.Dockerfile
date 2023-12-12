FROM rust:1.74-slim-bookworm

ARG APP_NAME=vsock-proxy
WORKDIR /app

COPY bin/vsock-proxy vsock-proxy

CMD ["/app/vsock-proxy"]
