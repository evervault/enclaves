const { expect } = require("chai");
const axios = require("axios").default;
const https = require("https");

describe("POST data to enclave", () => {
  const allowAllCerts = axios.create({
    httpsAgent: new https.Agent({
      rejectUnauthorized: false,
    }),
  });
  context("api key auth is disabled", () => {
    it("returns successfully", () => {
      return allowAllCerts
        .post("https://enclave.localhost:443/hello", { secret: "ev:123" })
        .then((result) => {
          console.log("Post request sent to the enclave");
          expect(result.data).to.deep.equal({
            response: "Hello from enclave",
            secret: "ev:123",
          });
        })
        .catch((err) => {
          console.error(err);
          throw err;
        });
    });
  });
});
