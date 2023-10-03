# vsock-proxy

A utility crate for proxying connections between TCP and Vsock.

## Install

```sh
cargo install vsock-proxy
```

## Examples

### Proxy from TCP to VSock

```sh
vsock-proxy --tcp-source 127.0.0.1:8008 --vsock-dest 1234:5678
```

### Proxy from VSock to TCP

```sh
vsock-proxy --vsock-source 3:6789 --tcp-dest 127.0.0.1:5000
```