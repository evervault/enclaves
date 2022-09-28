set -e 

# install the node modules for customer process and test script
cd e2e-tests && npm install && cd ..

# if not in CI, build in this script
if [[ -z "${CI}" ]];
then
  cargo build --features network_egress --release --target x86_64-unknown-linux-musl
  echo "Building cage container"
  docker build --platform=linux/amd64 --build-arg MOCK_CRYPTO_CERT=/node-services/testing.crt --build-arg MOCK_CRYPTO_KEY=/node-services/testing.key -f e2e-tests/Dockerfile -t cages-test .
else
  echo "Building cage container CI"
  docker build --build-arg=CI=true --build-arg MOCK_CRYPTO_CERT="$MOCK_CRYPTO_CERT" --build-arg MOCK_CRYPTO_KEY="$MOCK_CRYPTO_KEY" --platform=linux/amd64 -f e2e-tests/Dockerfile -t cages-test .
fi

echo "Running cage container"
# run the container
docker run -d --dns 127.0.0.1 -p 0.0.0.0:443:3031 --rm --name cages-test-container cages-test

sleep 2

echo "Running tests"
cd e2e-tests && npm run test

echo "Tests complete"
docker kill cages-test-container
