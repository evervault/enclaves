FROM rust:1.74-slim-bookworm

ARG APP_NAME=vsock-proxy
WORKDIR /app

COPY bin/vsock-proxy vsock-proxy

CMD ["/app/vsock-proxy --tcp-source '127.0.0.1:8008' --vsock-dest '2021:8001'"]
