FROM node:16-alpine3.15

ENV DATA_PLANE_EXECUTABLE_PATH=/data-plane
ENV DATA_PLANE_SERVICE_PATH=/etc/service/data-plane
ENV CONTROL_PLANE_EXECUTABLE_PATH=/control-plane
ENV CONTROL_PLANE_SERVICE_PATH=/etc/service/control-plane
ENV START_EV_SERVICES_PATH=/etc/service/ev-services-entrypoint


RUN apk update &&\
    apk add runit &&\
    rm -rf /var/cache/apk/*

COPY ./target/x86_64-unknown-linux-musl/release/data-plane $DATA_PLANE_EXECUTABLE_PATH
RUN chmod +x $DATA_PLANE_EXECUTABLE_PATH

COPY ./target/x86_64-unknown-linux-musl/release/control-plane $CONTROL_PLANE_EXECUTABLE_PATH
RUN chmod +x $CONTROL_PLANE_EXECUTABLE_PATH

RUN mkdir $DATA_PLANE_SERVICE_PATH
COPY ./tests/scripts/start-data-plane.sh $DATA_PLANE_SERVICE_PATH/run
RUN chmod +x $DATA_PLANE_SERVICE_PATH/run

RUN mkdir $CONTROL_PLANE_SERVICE_PATH
COPY ./tests/scripts/start-control-plane.sh $CONTROL_PLANE_SERVICE_PATH/run
RUN chmod +x $CONTROL_PLANE_SERVICE_PATH/run

COPY ./tests/customerProcess.js /customer-services/customerProcess.js
COPY ./tests/package.json /customer-services/package.json

RUN cd customer-services \
    && npm install

RUN mkdir /etc/service/customer_process \
    && /bin/sh -c "echo -e '"'#!/bin/sh\nexec /customer_process/customer_process\n'"' > /etc/service/customer_process/run" \
    && chmod +x /etc/service/customer_process/run

RUN mkdir /customer_process

COPY ./tests/scripts/start_customer_process /customer_process/customer_process
RUN chmod +x /customer_process/customer_process    

CMD ["runsvdir", "/etc/service"]
