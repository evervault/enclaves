FROM alpine:latest

ARG APP=/usr/src/app

EXPOSE 80

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN addgroup -S $APP_USER \
    && adduser -S -g $APP_USER $APP_USER

RUN apk update \
    && apk add --no-cache ca-certificates curl tzdata linux-headers \
    && rm -rf /var/cache/apk/*

COPY target/x86_64-unknown-linux-musl/release/acme-server ${APP}/acme-server

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}
ENV RUST_LOG=debug

ENTRYPOINT ["./acme-server"]