const express = require('express')
const app = express()
const port = 8008
app.use(express.json())

app.all('*', (req, res) => {
  res.send({response: "Hello from enclave", ...req.body})
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})