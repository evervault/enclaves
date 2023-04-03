const { default: axios } = require('axios')
const express = require('express')
const app = express()
const port = 8008
app.use(express.json())


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


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})