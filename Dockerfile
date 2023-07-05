FROM node:16-alpine3.15

ENV DATA_PLANE_EXECUTABLE_PATH=/data-plane
ENV DATA_PLANE_SERVICE_PATH=/etc/service/data-plane
ENV CONTROL_PLANE_EXECUTABLE_PATH=/control-plane
ENV CONTROL_PLANE_SERVICE_PATH=/etc/service/control-plane
ENV START_EV_SERVICES_PATH=/etc/service/ev-services-entrypoint

EXPOSE 443

RUN apk update &&\
    apk add runit && apk add curl \
    rm -rf /var/cache/apk/*

COPY ./target/x86_64-unknown-linux-musl/release/data-plane $DATA_PLANE_EXECUTABLE_PATH
RUN chmod +x $DATA_PLANE_EXECUTABLE_PATH

COPY ./target/x86_64-unknown-linux-musl/release/control-plane $CONTROL_PLANE_EXECUTABLE_PATH
RUN chmod +x $CONTROL_PLANE_EXECUTABLE_PATH

RUN mkdir $DATA_PLANE_SERVICE_PATH
COPY ./e2e-tests/scripts/start-data-plane.sh $DATA_PLANE_SERVICE_PATH/run
RUN chmod +x $DATA_PLANE_SERVICE_PATH/run

RUN mkdir $CONTROL_PLANE_SERVICE_PATH
COPY ./e2e-tests/mtls-testing-certs/ca/*  /$CONTROL_PLANE_SERVICE_PATH/
COPY ./e2e-tests/scripts/start-control-plane.sh $CONTROL_PLANE_SERVICE_PATH/run
RUN chmod +x $CONTROL_PLANE_SERVICE_PATH/run

ENV PCR0 000
ENV PCR1 000
ENV PCR2 000
ENV PCR8 000

# CERTS FOR CRYPTO API
ARG MOCK_CRYPTO_CERT
ARG MOCK_CRYPTO_KEY
ENV MOCK_CRYPTO_CERT $MOCK_CRYPTO_CERT
ENV MOCK_CRYPTO_KEY $MOCK_CRYPTO_KEY

# CERTS FOR CERT PROVISIONER
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

# USE HTTP OR WS CUSTOMER SERVER
ARG CUSTOMER_PROCESS=httpCustomerProcess.js

COPY ./e2e-tests/mock-crypto/target/x86_64-unknown-linux-musl/release/mock-crypto /services/
RUN chmod +x /services/mock-crypto

COPY ./e2e-tests/mockCertProvisionerApi.js ./e2e-tests/mtls-testing-certs/ca/* /services/
COPY ./e2e-tests/sample-ca/* /services/
COPY ./e2e-tests/$CUSTOMER_PROCESS /services/$CUSTOMER_PROCESS
COPY ./e2e-tests/package.json /services/package.json
COPY ./e2e-tests/package-lock.json /services/package-lock.json

RUN cd services && npm i

RUN mkdir /etc/service/customer_process \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /customer_process/customer_process ${CUSTOMER_PROCESS}\n'"' > /etc/service/customer_process/run" \
    && chmod +x /etc/service/customer_process/run

RUN mkdir /customer_process

COPY ./e2e-tests/scripts/start_customer_process /customer_process/customer_process
RUN chmod +x /customer_process/customer_process 

RUN mkdir /etc/service/mock_process \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /mock_process/mock_process\n'"' > /etc/service/mock_process/run" \
    && chmod +x /etc/service/mock_process/run

RUN mkdir /mock_process

COPY ./e2e-tests/scripts/start_mock_process /mock_process/mock_process
RUN chmod +x /mock_process/mock_process

RUN mkdir /etc/service/mock_cert_provisioner \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /mock_cert_provisioner/start_mock_cert_provisioner\n'"' > /etc/service/mock_cert_provisioner/run" \
    && chmod +x /etc/service/mock_cert_provisioner/run

RUN mkdir /mock_cert_provisioner

COPY ./e2e-tests/scripts/start_mock_cert_provisioner /mock_cert_provisioner/start_mock_cert_provisioner
RUN chmod +x /mock_cert_provisioner/start_mock_cert_provisioner

CMD ["runsvdir", "/etc/service"]
