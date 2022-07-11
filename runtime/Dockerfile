FROM alpine:3.15

ENV DATA_PLANE_EXECUTABLE_PATH=/data-plane
ENV DATA_PLANE_SERVICE_PATH=/etc/service/data-plane
ENV USER_ENTRYPOINT_SCRIPT_PATH=/user-entrypoint.sh
ENV USER_ENTRYPOINT_SERVICE_PATH=/etc/service/user-entrypoint

# install runit
RUN apk update &&\
    apk add runit &&\
    # clean apk cache
    rm -rf /var/cache/apk/*

# add data-plane executable
COPY ./target/x86_64-unknown-linux-musl/release/data-plane $DATA_PLANE_EXECUTABLE_PATH
RUN chmod +x $DATA_PLANE_EXECUTABLE_PATH

# add user-entrypoint script
COPY ./runtime/user-entrypoint.sh $USER_ENTRYPOINT_SCRIPT_PATH
RUN chmod +x $USER_ENTRYPOINT_SCRIPT_PATH

# add service for starting the data-plane
RUN mkdir $DATA_PLANE_SERVICE_PATH
COPY ./runtime/start-data-plane.sh $DATA_PLANE_SERVICE_PATH/run
RUN chmod +x $DATA_PLANE_SERVICE_PATH/run &&\
    # tell runit not to automatically run this service
    touch $DATA_PLANE_SERVICE_PATH/down

# add service for running the user's entrypoint, which also starts the data-plane service
RUN mkdir $USER_ENTRYPOINT_SERVICE_PATH
COPY ./runtime/run-user-entrypoint.sh $USER_ENTRYPOINT_SERVICE_PATH/run
RUN chmod +x $USER_ENTRYPOINT_SERVICE_PATH/run

CMD ["runsvdir", "/etc/service"]
