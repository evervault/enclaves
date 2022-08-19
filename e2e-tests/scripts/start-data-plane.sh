#!/bin/sh

export EV_APP_UUID=app_12345678
export EV_TEAM_UUID=team_12345678
export EV_CAGE_NAME=test-cage

echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

echo "Creating loopback interface"
ifconfig lo 127.0.0.1
exec $DATA_PLANE_EXECUTABLE_PATH