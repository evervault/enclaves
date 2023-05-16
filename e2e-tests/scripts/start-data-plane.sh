#!/bin/sh

echo {\"apiKeyAuth\":\"true\",\"egress\":{},\"trxLoggingEnabled\":\"true\"} > /etc/dataplane-config.json

exec $DATA_PLANE_EXECUTABLE_PATH
