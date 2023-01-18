#!/bin/bash
set -e 


# kill container if it is left running by hanging test, then generate local testing certs
if [[ -z "${CI}" ]];
then
  docker kill cages-test-container || true
  . e2e-tests/mtls-testing-certs/ca/generate-certs.sh &
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
docker build \
  --build-arg MOCK_CRYPTO_CERT="$MOCK_CRYPTO_CERT" \
  --build-arg MOCK_CRYPTO_KEY="$MOCK_CRYPTO_KEY" \
  --build-arg MOCK_CERT_PROVISIONER_CLIENT_CERT="$MOCK_CERT_PROVISIONER_CLIENT_CERT" \
  --build-arg MOCK_CERT_PROVISIONER_CLIENT_KEY="$MOCK_CERT_PROVISIONER_CLIENT_KEY" \
  --build-arg MOCK_CERT_PROVISIONER_ROOT_CERT="$MOCK_CERT_PROVISIONER_ROOT_CERT" \
  --build-arg MOCK_CERT_PROVISIONER_SERVER_KEY="$MOCK_CERT_PROVISIONER_SERVER_KEY" \
  --build-arg MOCK_CERT_PROVISIONER_SERVER_CERT="$MOCK_CERT_PROVISIONER_SERVER_CERT" \
  --platform=linux/amd64 \
  -f e2e-tests/Dockerfile \
  -t cages-test \
  .

docker_run_args="-d --dns 127.0.0.1 -p 0.0.0.0:443:3031 -p 0.0.0.0:3032:3032 --rm --name cages-no-tls-container"

echo "Running cage container"
# run the container
docker run $docker_run_args cages-test
echo "SLEEPING 15 SECONDS to let cage initialize..."
sleep 15

docker logs -t cages-no-tls-container | tail -n 1000

echo "Running end-to-end tests for cage without TLS termination"
cd e2e-tests && npm run no-tls-termination-tests || ($(docker logs -t cages-no-tls-container | tail -n 1000) && false)

echo "Tests complete"
docker kill cages-no-tls-container
