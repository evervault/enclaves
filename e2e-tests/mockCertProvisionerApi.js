const fs = require('fs');
const https = require('https')
const express = require('express')
const app = express()

console.log("Starting up mock cert provsioner");

app.use(express.json())
app.use(express.urlencoded({extended : true}));

const options = {
  key: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_SERVER_KEY : fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_SERVER_KEY, 'utf8'),
  cert: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_SERVER_CERT: fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_SERVER_CERT, 'utf8'),
  ca: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_ROOT_CERT: fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_ROOT_CERT, 'utf8'),
  port: 3443,
  requestCert: true,
  rejectUnauthorized: false
};

const mutualTlsMiddleware = () => (req, res, next) => {
  if (!req.client.authorized) {
    console.log("CLIENT NOT AUTHENTICATED");
    return res.status(401).send('Invalid client certificate authentication.');
  } else {
    console.log("CLIENT AUTHENTICATED")
    res.set("X-MTLS", "Authenticated")
  }
  return next();
};

app.use(mutualTlsMiddleware());


app.get('/cert/token', async (req, res) => {
  try {
    console.log(req.body);
    const { cageUuid, cage_version,  app_uuid} = req.body
    console.log("Received token request from cage control plane")
    var result = {
      token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    };
    res.status(200)
    res.send(result) 
  } catch (e) {
    console.log("Could not return cert token", e)
  }
})
 

https.createServer(options, app).listen(options.port, () => {
  console.log(`HTTPS MTLS mock cert provisioner server running on ${options.port}`)
})


const TlsOptions = {
  key: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_SERVER_KEY : fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_SERVER_KEY, 'utf8'),
  cert: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_SERVER_CERT: fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_SERVER_CERT, 'utf8'),
  ca: process.env.CI === "true" ? process.env.MOCK_CERT_PROVISIONER_ROOT_CERT: fs.readFileSync(process.env.MOCK_CERT_PROVISIONER_ROOT_CERT, 'utf8'),
  port: 3000,
};

const tlsApp = express()
tlsApp.post('/cert', async (req, res) => {
  try {
    let ca_cert = Buffer.from(fs.readFileSync('/services/sample-intermediate-cert.pem', 'utf8')).toString('base64');
    let ca_key_pair =  Buffer.from(fs.readFileSync('/services/sample-intermediate-key.pem', 'utf8')).toString('base64');

    console.log(`Mock cert provisioner - Received cert request from cage data plane ${req}`);
    
    var result = {
      intermediate_cert: ca_cert,
      key_pair: ca_key_pair
    };
    res.status(200)
    res.send(result) 
  } catch (e) {
    console.log("Could not return cert ", e)
  }
})
 

https.createServer(options, tlsApp).listen(TlsOptions.port, () => {
  console.log(__filename);
  console.log(`HTTPS mock cert provisioner server running on ${TlsOptions.port}`)
})


