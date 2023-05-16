#!/bin/sh

echo {\"api_key_auth\":true,\"egress\":{\"ports\": \"443\", \"allow_list\": \"jsonplaceholder.typicode.com\"},\"trx_logging_enabled\":true} > /etc/dataplane-config.json

exec $DATA_PLANE_EXECUTABLE_PATH
