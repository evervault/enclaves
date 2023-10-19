#!/bin/bash

# If sample-ca directory doesn't exist, create it
if [ ! -d "e2e-tests/sample-ca" ]; then
  mkdir -p e2e-tests/sample-ca
fi
# Generate self signed root CA
openssl genrsa -out e2e-tests/sample-ca/sample-root-ca-key.pem 2048
openssl req -x509 -extensions v3_ca -subj "/C=US/ST=CA/L=San Francisco/O=Evervault/OU=Cages/CN=Cage Test Root CA" -sha256 -new -nodes -key e2e-tests/sample-ca/sample-root-ca-key.pem -days 3650 -out e2e-tests/sample-ca/sample-root-ca-cert.pem
# Generate intermediate CA
openssl genrsa -out e2e-tests/sample-ca/sample-intermediate-key.pem 2048
openssl req -new -subj "/C=US/ST=CA/L=San Francisco/O=Evervault/OU=Cages/CN=Cage Test Intermediate CA" -addext "basicConstraints=critical,CA:TRUE" -key e2e-tests/sample-ca/sample-intermediate-key.pem -out e2e-tests/sample-ca/intermediate.csr
openssl x509 -copy_extensions copyall -req -in e2e-tests/sample-ca/intermediate.csr -CA e2e-tests/sample-ca/sample-root-ca-cert.pem -CAkey e2e-tests/sample-ca/sample-root-ca-key.pem -out e2e-tests/sample-ca/sample-intermediate-cert.pem -days 365 -sha256
rm e2e-tests/sample-ca/intermediate.csr