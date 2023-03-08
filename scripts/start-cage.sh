#!/bin/bash
INSTANCE_ID=$(wget -q -O - http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r ."instanceId")

export EC2_INSTANCE_ID=${INSTANCE_ID}

# Provision new enclave using customer config
echo "[HOST] Starting enclave..."

enclave_run_command="nitro-cli run-enclave --cpu-count $ENCLAVE_NUM_CPUS --memory $ENCLAVE_RAM_SIZE_MIB --enclave-cid 2021 --eif-path enclave.eif"

if [ "$ENCLAVE_DEBUG_MODE" = "true" ] ; then
  echo "[HOST] Debug mode enabled..."
  eval "$enclave_run_command --debug-mode"
else
  echo "[HOST] Debug mode disabled..."
  eval "$enclave_run_command"
fi

echo "[HOST] Enclave started... Waiting 5 seconds for warmup."
sleep 5

if [ "$ENCLAVE_DEBUG_MODE" = "true" ] ; then
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