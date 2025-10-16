FROM node:18-alpine3.21

ENV DATA_PLANE_EXECUTABLE_PATH=/data-plane
ENV DATA_PLANE_SERVICE_PATH=/etc/service/data-plane
ENV START_EV_SERVICES_PATH=/etc/service/ev-services-entrypoint

RUN apk update &&\
    apk add runit && apk add curl && \
    rm -rf /var/cache/apk/*
RUN apk add iptables

COPY ./target/x86_64-unknown-linux-musl/release/data-plane $DATA_PLANE_EXECUTABLE_PATH
RUN chmod +x $DATA_PLANE_EXECUTABLE_PATH

RUN mkdir $DATA_PLANE_SERVICE_PATH
COPY ./e2e-tests/scripts/start-data-plane.sh $DATA_PLANE_SERVICE_PATH/run
RUN chmod +x $DATA_PLANE_SERVICE_PATH/run

ENV PCR0 000
ENV PCR1 000
ENV PCR2 000
ENV PCR8 000

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

CMD ["runsvdir", "/etc/service"]
