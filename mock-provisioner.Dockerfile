FROM node:16-alpine3.18

ENV START_EV_SERVICES_PATH=/etc/service/ev-services-entrypoint

EXPOSE 3443
EXPOSE 3000

RUN apk update &&\
    apk add runit && apk add curl && \
    rm -rf /var/cache/apk/*

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