#!/bin/bash
set -e 

# kill container if it is left running by hanging test, then generate local testing certs
if [ "${CI:-unset}" = "unset" ];
then
  docker compose down || true
  cargo build --release --target x86_64-unknown-linux-musl --no-default-features
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

# Compile mock crypto api
if [[ -z "${CI}" ]];
then
  cd ./e2e-tests/mock-crypto
  cargo build --release --target x86_64-unknown-linux-musl
  cd ../..
fi

export CUSTOMER_PROCESS=httpCustomerProcess.js

echo "Building enclave container CI"
export EV_API_KEY_AUTH=true
docker compose build --build-arg CUSTOMER_PROCESS=httpCustomerProcess.js

echo "Running enclave container"
# run the container
docker compose up -d
echo "SLEEPING 15 SECONDS to let enclave initialize..."
sleep 15

docker compose logs --tail enclaves-enclaves

echo "Running end-to-end tests for enclave without TLS termination"
cd e2e-tests && npm run no-tls-termination-tests || ($(docker compose logs --tail enclaves-enclaves) && false)

echo "Tests complete"
docker compose down


