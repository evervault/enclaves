#!/bin/bash
yum install wget -y
INSTANCE_ID=$(wget -q -O - http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r ."instanceId")

export EC2_INSTANCE_ID=${INSTANCE_ID}

# Kill all existing enclaves on this host
echo "[HOST] Deployment started. Terminating old enclave..."
nitro-cli terminate-enclave --all
echo "[HOST] Enclave terminated. Waiting 10s..."
sleep 10

DEBUG_MODE="$(cat enclave.json | jq .debug_mode)"

# Provision new enclave using customer config
echo "[HOST] Starting enclave..."

if [ "$DEBUG_MODE" = true ] ; then
  echo "[HOST] Debug mode enabled..."
else
  echo "[HOST] Debug mode disabled..."
fi

nitro-cli run-enclave --config enclave.json
echo "[HOST] Enclave started... Waiting 10 seconds for warmup."
sleep 10

if [ "$DEBUG_MODE" = true ] ; then
  # Create stdout streams for any running enclaves
  echo "[HOST] Attaching headless console for running enclaves..."
  for id in $(nitro-cli describe-enclaves | jq -r ".[] | .EnclaveID")
  do
      # Create console listener
      nitro-cli console --enclave-id $id &
  done
fi

# Boot control plane
echo "[HOST] Starting control plane..."
exec ./control-plane