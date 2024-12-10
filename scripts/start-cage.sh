#!/bin/bash
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -sL`
INSTANCE_ID=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document -H "X-aws-ec2-metadata-token: $TOKEN" | jq -r ."instanceId")

export EC2_INSTANCE_ID=${INSTANCE_ID}

# Boot control plane
echo "[HOST] Starting control plane..."
exec ./control-plane