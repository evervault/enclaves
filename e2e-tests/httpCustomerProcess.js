const { default: axios } = require('axios')
const express = require('express')
const https = require('https');
const { SocksProxyAgent } = require('socks-proxy-agent');


const socksProxy = 'socks5://GHEiSzvU4Wr2WY2Y:wifi;;;;@proxy.soax.com:9000';
const agent = new SocksProxyAgent(socksProxy);

const app = express()
const port = 8008
app.use(express.json())
const ipv6HttpsAgent = new https.Agent({ family: 6 });

app.all('/hello', async (req, res) => { 
  res.send({response: "Hello from enclave", ...req.body})
})

app.get('/env', async (req, res) => {
  try {
    res.send({ANOTHER_ENV_VAR: process.env.ANOTHER_ENV_VAR})
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
})

app.get('/egress', async (req, res) => {
  try {
    const result = await axios.get("https://jsonplaceholder.typicode.com/posts/1")
    res.send({...result.data})
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
})

app.get('/egress-ipv6', async (req, res) => {
  try {
    const result = await axios.get("https://jsonplaceholder.typicode.com/posts/1", { httpsAgent: ipv6HttpsAgent })
    res.send({...result.data})
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
})


app.get('/egressBanned', async (req, res) => {
  try {
    const result = await axios.get("https://evervault.com")
    res.send({...result.data})
  } catch (e) {
    res.status(500).send(e)
  }
})

async function encrypt(payload) {
  const result = await axios.post("http://127.0.0.1:9999/encrypt", payload, { headers: { 'api-key': 'placeholder' } });
  return result.data;
}

app.post('/encrypt', async (req, res) => {
  try {
    const result = await encrypt(req.body);
    res.send(result)
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
})

async function decrypt(payload) {
  const result = await axios.post("http://127.0.0.1:9999/decrypt", payload, { headers: { 'api-key': 'placeholder' } });
  return result.data;
}

app.post('/crypto', async (req, res) => {
  try {
    const encrypted = await encrypt(req.body);
    const decrypted = await decrypt(encrypted);
    res.send({ encrypted, decrypted });
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
});

app.post('/attestation-doc', async (req, res) => {
  try {
    const result = await axios.post("http://127.0.0.1:9999/attestation-doc", req.body, { headers: { 'api-key': 'placeholder' }, responseType: "arraybuffer"})
    res.send(result.data)
  } catch (e) {
    console.log("Failed", e)
    res.status(500).send(e)
  }
})


app.all("/chunked", async (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('transfer-encoding', 'chunked');
    const responseData = { response: 'Hello from enclave', ...req.body };

    const jsonStr = JSON.stringify(responseData);

    const chunkSize = 20;

    for (let i = 0; i < jsonStr.length; i += chunkSize) {
      const chunk = jsonStr.slice(i, i + chunkSize);
      res.write(chunk);
    }

    res.end();
  } catch (err) {
    console.log("Could not handle hello request", err);
    res.status(500).send({msg: "Error from within the cage!"})
  }
});


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})