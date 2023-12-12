import { VsockSocket } from "node-vsock"

const client = new VsockSocket();
const cid = 2021;
const port = 8001;

client.on('error', (err) => {
  console.log("err: ", err)
});

client.connect(cid, port, async () => {
  const data = ['hello', 'w', 'o', 'r', 'l', 'd'];

  client.on('data', (buf) => {
    console.log("recv: ", buf.toString())
  })

  for (const str of data) {
    client.writeTextSync(str);
  }

  client.end();
});
