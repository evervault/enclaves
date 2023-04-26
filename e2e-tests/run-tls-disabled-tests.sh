#!/bin/bash
set -e 


# kill container if it is left running by hanging test, then generate local testing certs
if [[ -z "${CI}" ]];
then
  docker compose down || true
  cargo build --release --target x86_64-unknown-linux-musl --no-default-features
  . e2e-tests/mtls-testing-certs/ca/generate-certs.sh &
else
  # if in CI, generate certs and export them
  . e2e-tests/mtls-testing-certs/ca/generate-certs.sh
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


echo "Building cage container CI"
docker compose build 

echo "Running cage container"
# run the container
docker compose up -d
echo "SLEEPING 15 SECONDS to let cage initialize..."
sleep 15

docker compose logs --tail cages-cages

echo "Running end-to-end tests for cage without TLS termination"
cd e2e-tests && npm run no-tls-termination-tests || ($(docker compose logs --tail cages-cages) && false)

echo "Tests complete"
docker compose down


