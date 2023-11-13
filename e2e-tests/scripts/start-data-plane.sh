#!/bin/sh

echo {\"api_key_auth\":${EV_API_KEY_AUTH},\"egress\":{\"ports\": \"443\", \"allow_list\": \"jsonplaceholder.typicode.com\"},\"trx_logging_enabled\":true,\"forward_proxy_protocol\":false,\"trusted_headers\": []} > /etc/dataplane-config.json

SYSTEM_STATS_INTERVAL=1 exec $DATA_PLANE_EXECUTABLE_PATH
