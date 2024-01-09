#!/bin/sh

echo {\"api_key_auth\":${EV_API_KEY_AUTH},\"egress\":{\"allow_list\": \"*\"},\"trx_logging_enabled\":true,\"forward_proxy_protocol\":false,\"trusted_headers\": []} > /etc/dataplane-config.json

iptables -A OUTPUT -t nat -p tcp --dport 443 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:4444

SYSTEM_STATS_INTERVAL=1 exec $DATA_PLANE_EXECUTABLE_PATH
