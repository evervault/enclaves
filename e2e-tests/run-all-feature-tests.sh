#!/bin/bash
set -e 


# kill container if it is left running by hanging test, then generate local testing certs
if [[ -z "${CI}" ]];
then
  docker compose down || true
  cargo build --release --target x86_64-unknown-linux-musl --features network_egress
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
  cargo build --release --target x86_64-unknown-linux-musl -Z registry-auth
  cd ../..
fi


echo "Building cage container"
docker compose build

echo "Running cage container"
# run the container
docker compose up -d
echo "SLEEPING 15 SECONDS to let cage initialize..."
sleep 15

docker compose logs --tail cages-cages

echo "Running end-to-end tests"
cd e2e-tests && npm run test || ($(docker compose logs --tail cages-cages) && false)

echo "Running tests for health-check configurations"

echo "data-plane health checks ON, control-plane ON, data-plane ON"
npm run health-check-tests "should succeed"

echo "data-plane health checks ON, control-plane ON, data-plane OFF"
docker compose exec cages sh -c "sv down data-plane"
npm run health-check-tests "should fail"

echo "data-plane health checks OFF, control-plane ON, data-plane OFF"
docker compose down
EV_DATA_PLANE_HEALTH_CHECKS=false docker compose up -d 
docker compose exec cages sh -c "sv down data-plane"
npm run health-check-tests "should succeed"

echo "API Key Auth Tests"
docker compose down
EV_API_KEY_AUTH=true docker compose up -d
sleep 10
npm run api-key-auth-tests

echo "No API Key Auth Tests"
docker compose down
EV_API_KEY_AUTH=false docker compose up -d
sleep 10
npm run no-auth-tests

echo "Testing that Cage is serving trustable cert chain"
echo "Q" | openssl s_client -verifyCAfile sample-ca/sample-root-ca-cert.pem -showcerts -connect 0.0.0.0:443 | grep "Verification: OK"


echo "Tests complete"
docker compose down

