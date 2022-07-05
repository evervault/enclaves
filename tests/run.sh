
cd control-plane && sudo cargo run --features "network_egress" &
cd data-plane && sudo cargo run --features "network_egress" &

cd tests
npm install
npm run customer &

npm run test

kill -9 $(lsof -t -i tcp:8008)
kill -9 $(lsof -t -i tcp:7777)
kill -9 $(lsof -t -i tcp:3030)

