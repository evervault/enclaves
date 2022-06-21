
cd control-plane && cargo build && cargo run &
cd data-plane && cargo build && cargo run &

cd tests
npm install
npm run customer &

npm run test

kill -9 $(lsof -t -i tcp:8008)
kill -9 $(lsof -t -i tcp:7777)
kill -9 $(lsof -t -i tcp:3030)

