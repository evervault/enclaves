#!/bin/bash

# Kill all existing enclaves on this host
nitro-cli terminate-enclave --all
echo "Enclave terminated. Waiting 10s..."
sleep 10
# Provision new enclave using customer config
echo "Starting enclave..."
nitro-cli run-enclave --config enclave.json
echo "Enclave started... waiting 5 seconds for warmup"

# Create stdout streams for any running enclaves
# for id in $(nitro-cli describe-enclaves | jq -r ".[] | .EnclaveID")
# do
#   	nitro-cli console --enclave-id $id &
# done

# Boot control plane
echo "Starting control plane..."
exec ./control-plane