#!/bin/bash

DELIMETER="*****************************"

emit_msg() {
  echo "$DELIMETER"
  echo "$1"
  echo "$DELIMETER"
}

PLATFORM=$(uname -s)
if [ "$PLATFORM" = "Darwin" ]; then
  emit_msg "Detected MacOS, setting path to use homebrew openssl"
  export PATH=$(brew --prefix openssl)/bin:$PATH #make sure openssl is linked, not libressl
fi

mkdir -p certs 
cd certs

emit_msg "BEGINNING PROCESS TO GENERATE CERTS"

emit_msg "GENERATING KEY FOR CA"
openssl genrsa -out ca.key 2048

emit_msg "GENERATING A SELF SIGNED CERT FOR THE CA"
openssl req -subj "/C=IE/ST=Leinster/L=Dublin/O=Evervault/OU=Engineering/CN=support@evervault.com" -new -x509 -key ca.key -out ca.crt

emit_msg "GENERATING RSA KEY FOR SERVER AT localhost"
openssl genrsa -out localhost.key 2048

emit_msg "GENERATING CSR FOR SERVER CERT. MAKE SURE TO SET COMMON NAME AS localhost"
openssl req -subj "/C=IE/ST=Leinster/L=Dublin/O=Evervault/OU=Engineering/CN=support@evervault.com" -new -key localhost.key -addext "subjectAltName = DNS:localhost" -out localhost.csr

emit_msg "GENERATING A CERT SIGNED BY THE CA"
printf "subjectAltName=DNS:localhost" > extfile.cnf
openssl x509 -req -in localhost.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile extfile.cnf -out localhost.crt

emit_msg "GENERATING RSA KEY FOR CLIENT"
openssl genrsa -out client_0.key 2048

emit_msg "GENERATING CSR FOR CLIENT CERT. MAKE SURE TO SET COMMON NAME AS localhost"
openssl req -subj "/C=IE/ST=Leinster/L=Dublin/O=Evervault/OU=Engineering/CN=support@evervault.com" -new -key client_0.key -addext "subjectAltName = DNS:localhost" -out client_0.csr

emit_msg "GENERATING A CLIENT CERT SIGNED BY THE CA"
openssl x509 -req -subj "/C=IE/ST=Leinster/L=Dublin/O=Evervault/OU=Engineering/CN=support@evervault.com" -in client_0.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile extfile.cnf -out client_0.crt
rm extfile.cnf

emit_msg "GENERATED CERTS FOR MTLS TESTING"

cd ..