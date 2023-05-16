#!/bin/sh

echo {"apiKeyAuth":true,"egress":{"ports":"443", allowList:"*"},"trxLoggingEnabled":"true" > /etc/dataplane-config.json

exec $DATA_PLANE_EXECUTABLE_PATH
