set -e 

cd tests && npm install && cd ..
cargo build --features network_egress --release --target x86_64-unknown-linux-musl
docker build --platform linux/amd64 -t cages-test -f tests/Dockerfile .
docker run -d --dns 127.0.0.1 -p 0.0.0.0:3030:3031 -it --rm --name cages-test-container cages-test

sleep 2

cd tests
npm install
npm run test

docker kill cages-test-container
