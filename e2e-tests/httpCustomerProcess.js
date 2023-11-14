const { default: axios } = require('axios')
const express = require('express')
const app = express()
const port = 8008
app.use(express.json())
const { SocksProxyAgent } = require('socks-proxy-agent');
const { SocksClient } = require('socks');

const proxyOptions = {
    proxy: {
        host: '',
        port: 9000,   // Proxy port
        type: 5,                        // Proxy version (5 for SOCKS5)
        userId: '',        // Proxy username
        password: '',      // Proxy password
    },
    command: 'connect',
    destination: {
        host: 'jsonplaceholder.typicode.com',  // Destination hostname
        port: 443              // Destination port
    }
};

async function makeRequest() {
    try {
        const info = await SocksClient.createConnection(proxyOptions);

        const agent = new SocksProxyAgent({
            host: proxyOptions.destination.host,
            port: proxyOptions.destination.port,
            socket: info.socket,
        });

        const response = await axios.get(`http://${proxyOptions.destination.host}`, { httpAgent: agent });
        console.log(response.data);
    } catch (error) {
        console.error('Error:', error);
    }
}

app.all('/hello', async (req, res) => { 
  const response = await makeRequest('https://jsonplaceholder.typicode.com/todos/1');
  res.send({response: "Hello from enclave", response})
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