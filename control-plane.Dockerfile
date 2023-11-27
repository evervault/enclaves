FROM node:16-alpine3.18

ENV CONTROL_PLANE_EXECUTABLE_PATH=/control-plane
ENV CONTROL_PLANE_SERVICE_PATH=/etc/service/control-plane

EXPOSE 443

# CERTS FOR CRYPTO API
ARG MOCK_CRYPTO_CERT
ARG MOCK_CRYPTO_KEY
ENV MOCK_CRYPTO_CERT $MOCK_CRYPTO_CERT
ENV MOCK_CRYPTO_KEY $MOCK_CRYPTO_KEY

RUN apk update &&\
    apk add runit && apk add curl && \
    rm -rf /var/cache/apk/*

COPY ./e2e-tests/mock-crypto/target/x86_64-unknown-linux-musl/release/mock-crypto /services/
RUN chmod +x /services/mock-crypto  

RUN mkdir /etc/service/mock_process \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /mock_process/mock_process\n'"' > /etc/service/mock_process/run" \
    && chmod +x /etc/service/mock_process/run

RUN mkdir /mock_process

COPY ./e2e-tests/scripts/start_mock_process /mock_process/mock_process
RUN chmod +x /mock_process/mock_process

COPY ./target/x86_64-unknown-linux-musl/release/control-plane $CONTROL_PLANE_EXECUTABLE_PATH
RUN chmod +x $CONTROL_PLANE_EXECUTABLE_PATH

RUN mkdir $CONTROL_PLANE_SERVICE_PATH
COPY ./e2e-tests/mtls-testing-certs/ca/*  /$CONTROL_PLANE_SERVICE_PATH/
COPY ./e2e-tests/scripts/start-control-plane.sh $CONTROL_PLANE_SERVICE_PATH/run
RUN chmod +x $CONTROL_PLANE_SERVICE_PATH/run

CMD ["runsvdir", "/etc/service"]
