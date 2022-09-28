const { default: axios } = require('axios')
const express = require('express')
const app = express()
const port = 8008
app.use(express.json())


app.all('/hello', async (req, res) => {
  res.send({response: "Hello from enclave", ...req.body})
})


app.get('/egress', async (req, res) => {
  try {
    const result = await axios.get("https://jsonplaceholder.typicode.com/posts/1")
    res.send({...result.data})
  } catch (e) {
    console.log("Failed", e)
  }
})

app.post('/encrypt', async (req, res) => {
  try {
    const result = await axios.post("http://127.0.0.1:9999/encrypt", req.body, { headers: { 'api-key': 'placeholder' } })
    console.log("Encrypt result", result.data)
    res.send(result.data)
  } catch (e) {
    console.log("Failed", e)
  }
})

app.post('/decrypt', async (req, res) => {
  try {
    const result = await axios.post("http://127.0.0.1:9999/decrypt", req.body, { headers: { 'api-key': 'placeholder' } })
    res.send({...result.data})
  } catch (e) {
    console.log("Failed", e)
  }
})

app.post('/attestation-doc', async (req, res) => {
  try {
    const result = await axios.post("http://127.0.0.1:9999/attestation-doc", req.body, { headers: { 'api-key': 'placeholder' }, responseType: "arraybuffer"})
    res.send(result.data)
  } catch (e) {
    console.log("Failed", e)
  }
})


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})