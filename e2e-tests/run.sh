set -e 

# kill container if it is left running by hanging test
if [[ -z "${CI}" ]];
then
  docker kill cages-test-container || true
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

# if not in CI, build in this script
if [[ -z "${CI}" ]];
then
  cargo build --features network_egress --release --target x86_64-unknown-linux-musl
  echo "Building cage container"
  docker build --platform=linux/amd64 --build-arg MOCK_CRYPTO_CERT=/services/testing.crt --build-arg MOCK_CRYPTO_KEY=/services/testing.key -f e2e-tests/Dockerfile -t cages-test .
else
  echo "Building cage container CI"
  docker build --build-arg=CI=true --build-arg MOCK_CRYPTO_CERT="$MOCK_CRYPTO_CERT" --build-arg MOCK_CRYPTO_KEY="$MOCK_CRYPTO_KEY" --platform=linux/amd64 -f e2e-tests/Dockerfile -t cages-test .
fi

docker_run_args="-d --dns 127.0.0.1 -p 0.0.0.0:443:3031 -p 0.0.0.0:3032:3032 --rm --name cages-test-container"

echo "Running cage container"
# run the container
docker run $docker_run_args cages-test
if [[ -z "${CI}" ]];
then
  # pipe stdout and stderr out from test container for debugging when not in CI
  docker logs -f cages-test-container &> logs.txt &
fi
sleep 10

echo "Running end-to-end tests"
cd e2e-tests && npm run test

echo "Running tests for health-check configurations"

echo "data-plane health checks ON, control-plane ON, data-plane ON"
npm run health-check-tests "should succeed"

echo "data-plane health checks ON, control-plane ON, data-plane OFF"
docker exec cages-test-container sh -c "sv down data-plane"
npm run health-check-tests "should fail"

echo "data-plane health checks OFF, control-plane ON, data-plane OFF"
docker kill cages-test-container
docker run $docker_run_args --env DATA_PLANE_HEALTH_CHECKS=false cages-test
docker exec cages-test-container sh -c "sv down data-plane"
npm run health-check-tests "should succeed"

echo "Tests complete"
docker kill cages-test-container
