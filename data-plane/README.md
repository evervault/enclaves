# Cage Data Plane

The data plane is the Evervault managed process which runs within the Enclave to terminate TLS, perform decryption, and 
proxy any network egress.

## Local Development

If running the data-plane locally, you will need to generate a cert and private key. 

We suggest using [mkcert](https://github.com/FiloSottile/mkcert):

```shell
# install mkcert as a trusted CA
mkcert -install

# generate a cert and key for the data-plane
mkcert data-plane.localhost
```
