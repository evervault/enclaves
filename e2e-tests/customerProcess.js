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


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})