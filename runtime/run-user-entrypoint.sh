#!/bin/sh

# start the data-plane service
sv start data-plane
# wait for the data-plane service to be running
while !(sv check data-plane); do sleep 1; done;

# run the long-running user entrypoint
exec $USER_ENTRYPOINT_SCRIPT_PATH
