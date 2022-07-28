set -e 

# install the node modules for customer process and test script
cd e2e-tests && npm install && cd ..

# if not in CI, build in this script
if [[ -z "${CI}" ]]; then
    cargo build --features network_egress --release --target x86_64-unknown-linux-musl
fi

echo "Building cage container"
# build container which has control plane, data-plane and sample user process
docker build --platform=linux/amd64 -f e2e-tests/Dockerfile -t cages-test .

echo "Running cage container"
# run the container
docker run -d --dns 127.0.0.1 -p 0.0.0.0:443:3031 --rm --name cages-test-container cages-test

sleep 2

echo "Running tests"
cd e2e-tests && npm run test

echo "Tests complete"
docker kill cages-test-container