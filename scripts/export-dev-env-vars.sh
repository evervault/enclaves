export MOCK_CRYPTO_CERT=`cat certs/ca.crt`
export MOCK_CRYPTO_KEY=`cat certs/ca.key`
export MOCK_CERT_PROVISIONER_CLIENT_CERT=`cat certs/client_0.crt`
export MOCK_CERT_PROVISIONER_CLIENT_KEY=`cat certs/client_0.key`
export MOCK_CERT_PROVISIONER_ROOT_CERT=`cat certs/ca.crt`
export MOCK_CERT_PROVISIONER_SERVER_KEY=`cat certs/provisioner.key`
export MOCK_CERT_PROVISIONER_ROOT_CERT=`cat certs/ca.crt`
export MOCK_CERT_PROVISIONER_SERVER_CERT=`cat certs/provisioner.crt`
export EV_API_KEY_AUTH=true
export CUSTOMER_PROCESS=httpCustomerProcess.js
export ACME_ACCOUNT_EC_KEY=`cat ./e2e-tests/acme-key/key.pem`
export ACME_ACCOUNT_HMAC_KEY="cGxhY2Vob2xkZXI="
export ACME_ACCOUNT_HMAC_KEY_ID="placeholder_id"