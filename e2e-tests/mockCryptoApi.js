const crypto = require ("crypto");
const fs = require('fs');
const https = require('https')
const CBOR = require('cbor-sync');
const express = require('express')
const app = express()


app.use(express.json())
app.use(express.urlencoded({extended : true}));

const httpsPort = 7676;
const port = 7677;

const serverOpt = {
  key: process.env.CI ? process.env.MOCK_CRYPTO_KEY : fs.readFileSync(process.env.MOCK_CRYPTO_KEY),
  cert: process.env.CI ? process.env.MOCK_CRYPTO_CERT: fs.readFileSync(process.env.MOCK_CRYPTO_CERT)
};

const cryptoOpt = {
  algorithm: 'aes256',
  key: crypto.randomBytes(32),
  iv: crypto.randomBytes(16) 
};

app.post('/encrypt', async (req, res) => {
  try {
    const { teamUuid, appUuid, data } = req.body
    var result = {};
    Object.keys(data).forEach((key, _) => {
      result[key] = encrypt(data[key]);
    }); 
    res.send({teamUuid, appUuid, data: result}) 
  } catch (e) {
    console.log("Could not encrypt", e)
  }
})

app.post('/decrypt', (req, res) => {
  try {
    const { teamUuid, appUuid, data } = req.body
    var result = {};
    Object.keys(data).forEach((key, _) => {
      result[key] = decrypt(data[key]);
    });
    res.send({teamUuid, appUuid, data: result})
  } catch (e) {
    console.log("Could not decrypt", e)
  }
})

app.post('/attestation-doc', (req, res) => {
  try {
    var encodedBuffer = CBOR.encode({
        Measurements: { 
          PCR0: process.env.PCR0, 
          PCR1: process.env.PCR1, 
          PCR2: process.env.PCR2,
          PCR8: process.env.PCR8
        }});
    res.send(encodedBuffer)
  } catch (e) {
    console.log("Could not get attesation doc", e)
  }
})

const encrypt = (text) => {
  const cipher = crypto.createCipheriv(cryptoOpt.algorithm, cryptoOpt.key, cryptoOpt.iv);
  var encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex');
  return encrypted;
}
 
const decrypt = (text) => {
  const decipher = crypto.createDecipheriv(cryptoOpt.algorithm, cryptoOpt.key, cryptoOpt.iv);
  var decrypted = decipher.update(text, 'hex', 'utf8')
  decrypted += decipher.final('utf8');
  return decrypted;
}
 

https.createServer(serverOpt, app).listen(httpsPort, () => {
  console.log(`HTTPS mocks running on ${httpsPort}`)
})

app.listen(port, () => {
  console.log(`HTTP mocks running on ${port}`)
})

