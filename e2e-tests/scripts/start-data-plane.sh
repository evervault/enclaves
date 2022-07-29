#!/bin/sh

echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

echo "Creating loopback interface"
ifconfig lo 127.0.0.1
exec $DATA_PLANE_EXECUTABLE_PATH