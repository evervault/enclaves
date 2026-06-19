#!/bin/sh

echo {\"api_key_auth\":${EV_API_KEY_AUTH},\"egress\":{\"allow_list\": \"jsonplaceholder.typicode.com\"},\"trx_logging_enabled\":true,\"forward_proxy_protocol\":false,\"trusted_headers\": [],\"acceptor\":{\"max_concurrent_connections\":1024,\"max_concurrent_handshakes\":64,\"handshake_timeout\":{\"secs\":10,\"nanos\":0}}} > /etc/dataplane-config.json

iptables -A OUTPUT -t nat -p tcp --dport 443 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:4444

SYSTEM_STATS_INTERVAL=1 exec $DATA_PLANE_EXECUTABLE_PATH
