#!/bin/bash
set -e 

# kill container if it is left running by hanging test, then generate local testing certs
if [ "${CI:-unset}" = "unset" ];
then
  docker compose down || true
  cargo build --release --target x86_64-unknown-linux-musl --features network_egress
  . e2e-tests/mtls-testing-certs/ca/generate-certs.sh &
else 
  # if in CI, generate certs and export them
  . e2e-tests/mtls-testing-certs/ca/generate-certs.sh

  MOCK_CRYPTO_CERT=`cat certs/ca.crt` && export MOCK_CRYPTO_CERT
  MOCK_CRYPTO_KEY=`cat certs/ca.key` && export MOCK_CRYPTO_KEY


  MOCK_CERT_PROVISIONER_CLIENT_CERT=`cat certs/client_0.crt` && export MOCK_CERT_PROVISIONER_CLIENT_CERT
  MOCK_CERT_PROVISIONER_CLIENT_KEY=`cat certs/client_0.key` && export MOCK_CERT_PROVISIONER_CLIENT_KEY
  MOCK_CERT_PROVISIONER_ROOT_CERT=`cat certs/ca.crt` && export MOCK_CERT_PROVISIONER_ROOT_CERT

  MOCK_CERT_PROVISIONER_SERVER_KEY=`cat certs/localhost.key` && export MOCK_CERT_PROVISIONER_SERVER_KEY
  MOCK_CERT_PROVISIONER_ROOT_CERT=`cat certs/ca.crt` && export MOCK_CERT_PROVISIONER_ROOT_CERT
  MOCK_CERT_PROVISIONER_SERVER_CERT=`cat certs/localhost.crt` && export MOCK_CERT_PROVISIONER_SERVER_CERT
  ACME_ACCOUNT_EC_KEY=`cat ./e2e-tests/acme-key/key.pem` && export ACME_ACCOUNT_EC_KEY
  ACME_ACCOUNT_HMAC_KEY="cGxhY2Vob2xkZXI=" && export ACME_ACCOUNT_HMAC_KEY
  ACME_ACCOUNT_HMAC_KEY_ID="placeholder_id" && export ACME_ACCOUNT_HMAC_KEY_ID
fi

# install the node modules for customer process and test script
cd e2e-tests && npm install && cd ..

export TEST_EGRESS_IP=$(dig +short jsonplaceholder.typicode.com | head -n 1)

# Compile mock crypto api
if [[ -z "${CI}" ]];
then
  cd ./e2e-tests/mock-crypto
  cargo build --release --target x86_64-unknown-linux-musl
  cd ../..
fi

export CUSTOMER_PROCESS=httpCustomerProcess.js
echo "Building enclave setup"
export EV_API_KEY_AUTH=true
docker compose build --build-arg CUSTOMER_PROCESS=httpCustomerProcess.js

echo "Running enclave local setup"
# run the container
docker compose up -d
echo "SLEEPING 15 SECONDS to let enclave initialize..."
sleep 15

docker compose logs --tail cages-enclave

echo "Running end-to-end tests"
cd e2e-tests && npm run test || ($(docker compose logs --tail cages-enclave) && false)

echo "Running tests for health-check configurations"

echo "data-plane health checks ON, control-plane ON, data-plane ON"
npm run health-check-tests "should succeed"

echo "data-plane health checks ON, control-plane ON, data-plane OFF"
docker compose exec enclave sh -c "sv down data-plane"
npm run health-check-tests "should fail"

echo "API Key Auth Tests"
docker compose down
docker compose up -d
sleep 10
npm run api-key-auth-tests

echo "No API Key Auth Tests"
docker compose down
export EV_API_KEY_AUTH=false
docker compose up -d
sleep 10
npm run no-auth-tests

echo "Websocket Tests"
export EV_API_KEY_AUTH=true
export CUSTOMER_PROCESS=wsCustomerProcess.js
docker compose down
docker compose build --build-arg CUSTOMER_PROCESS=wsCustomerProcess.js
docker compose up -d
docker compose logs --tail cages-enclave
sleep 10
npm run websocket-tests

echo "Testing that enclave is serving trustable cert chain"
echo "Q" | openssl s_client -verifyCAfile sample-ca/sample-root-ca-cert.pem -showcerts -connect 0.0.0.0:443 | grep "Verification: OK"

echo "Tests complete"
docker compose down

