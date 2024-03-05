FROM node:16-alpine3.18

ENV CONTROL_PLANE_EXECUTABLE_PATH=/control-plane
ENV CONTROL_PLANE_SERVICE_PATH=/etc/service/control-plane


# CERTS FOR CRYPTO API
ARG MOCK_CRYPTO_CERT
ARG MOCK_CRYPTO_KEY
ENV MOCK_CRYPTO_CERT $MOCK_CRYPTO_CERT
ENV MOCK_CRYPTO_KEY $MOCK_CRYPTO_KEY

ARG MOCK_CERT_PROVISIONER_CLIENT_CERT
ARG MOCK_CERT_PROVISIONER_CLIENT_KEY
ARG MOCK_CERT_PROVISIONER_ROOT_CERT
ARG MOCK_CERT_PROVISIONER_SERVER_KEY
ARG MOCK_CERT_PROVISIONER_SERVER_CERT
ENV MOCK_CERT_PROVISIONER_CLIENT_CERT $MOCK_CERT_PROVISIONER_CLIENT_CERT
ENV MOCK_CERT_PROVISIONER_CLIENT_KEY $MOCK_CERT_PROVISIONER_CLIENT_KEY
ENV MOCK_CERT_PROVISIONER_ROOT_CERT $MOCK_CERT_PROVISIONER_ROOT_CERT
ENV MOCK_CERT_PROVISIONER_SERVER_KEY $MOCK_CERT_PROVISIONER_SERVER_KEY
ENV MOCK_CERT_PROVISIONER_SERVER_CERT $MOCK_CERT_PROVISIONER_SERVER_CERT

ARG EV_APP_UUID 
ENV EV_APP_UUID $EV_APP_UUID
ARG EV_API_KEY
ENV EV_API_KEY $EV_API_KEY

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

COPY ./e2e-tests/mockCertProvisionerApi.js ./e2e-tests/mtls-testing-certs/ca/* /services/
COPY ./e2e-tests/sample-ca/* /services/
COPY ./e2e-tests/package.json /services/package.json
COPY ./e2e-tests/package-lock.json /services/package-lock.json

RUN cd services && npm i

RUN mkdir /etc/service/mock_cert_provisioner \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /mock_cert_provisioner/start_mock_cert_provisioner\n'"' > /etc/service/mock_cert_provisioner/run" \
    && chmod +x /etc/service/mock_cert_provisioner/run

RUN mkdir /mock_cert_provisioner

COPY ./e2e-tests/scripts/start_mock_cert_provisioner /mock_cert_provisioner/start_mock_cert_provisioner
RUN chmod +x /mock_cert_provisioner/start_mock_cert_provisioner

CMD ["runsvdir", "/etc/service"]
