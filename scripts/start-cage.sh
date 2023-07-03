#!/bin/bash
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -sL`
INSTANCE_ID=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document -H "X-aws-ec2-metadata-token: $TOKEN" | jq -r ."instanceId")

export EC2_INSTANCE_ID=${INSTANCE_ID}

describe_res=$(nitro-cli describe-enclaves)

enclaves=($(echo "$describe_res" | jq -c '.[]'))

if [[ ${#enclaves[@]} -gt 0 ]]; then
  echo "[HOST] There is an enclave already running on this host. Terminating it..."
  nitro-cli terminate-enclave --all
  echo "[HOST] Enclave terminated. Waiting 10s..."
  sleep 10
else
  echo "[HOST] No enclaves currently running on this host."
fi


# Provision new enclave using customer config
echo "[HOST] Starting new enclave..."

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