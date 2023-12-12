# `Node VSock`

![https://github.com/wei-rong-1/node-vsock/actions](https://github.com/wei-rong-1/node-vsock/workflows/CI/badge.svg)

> A Node.js addon for VSOCK socket, [napi-rs](https://napi.rs/) based. Only support linux currently.

## Install this package

```
npm install --save node-vsock

yarn add node-vsock
```

## Support OS

|                  | node14 | node16 | node18 |
| ---------------- | ------ | ------ | ------ |
| Windows x64      | x      | x      | x      |
| Windows x32      | x      | x      | x      |
| Windows arm64    | x      | x      | x      |
| macOS x64        | x      | x      | x      |
| macOS arm64      | x      | x      | x      |
| Linux x64 gnu    | ✓      | ✓      | ✓      |
| Linux x64 musl   | ✓      | ✓      | ✓      |
| Linux arm gnu    | ✓      | ✓      | ✓      |
| Linux arm64 gnu  | ✓      | ✓      | ✓      |
| Linux arm64 musl | ✓      | ✓      | ✓      |
| Android arm64    | x      | x      | x      |
| Android armv7    | x      | x      | x      |
| FreeBSD x64      | x      | x      | x      |

## Example

```
import { VsockSocket } from "node-vsock"

const client = new VsockSocket();
const cid = 15;
const port = 9001;

client.on('error', (err:Error) => {
  console.log("err: ", err)
});

client.connect(cid, port, async () => {
  const data = ['hello', 'w', 'o', 'r', 'l', 'd'];

  client.on('data', (buf: Buffer) => {
    console.log("recv: ", buf.toString())
  })

  for (const str of data) {
    client.writeTextSync(str);
  }

  client.end();
});
```

A simple server side example:

```
import { VsockServer, VsockSocket } from 'node-vsock'

const server = new VsockServer();
const port = 9001;

server.on('error', (err: Error) => {
  console.log("err: ", err)
});

server.on('connection', (socket: VsockSocket) => {
  console.log("new socket connection..")

  socket.on('error', (err) => {
    console.log("socket err: ", err)
  });

  socket.on('data', (buf: Buffer) => {
    socket.writeTextSync(`I hear you! ${buf.toString()}`)
  });

  // socket.end()
});

server.listen(port);
```

## Develop requirements

- Install the latest `Rust`
- Install `Node.js@11+` which fully supported `Node-API v3`
- Install `yarn@1.x`

## Test in local

- yarn
- yarn build
- yarn test

## Lisence

MIT
