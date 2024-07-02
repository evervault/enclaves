const { expect } = require('chai');
const axios = require('axios').default;
const https = require('https');
const net = require("net");
const CBOR = require("cbor-sync");

describe("POST data to enclave", () => {
  const allowAllCerts = axios.create({
    httpsAgent: new https.Agent({
      rejectUnauthorized: false,
    }),
  });

  it("enclave responds and echos back body", () => {
    return allowAllCerts
      .post(
        "https://enclave.localhost:443/hello",
        { secret: "ev:123" },
        { headers: { "api-key": "placeholder" } }
      )
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

  it("calls out to the internet for allowed domain", () => {
    console.log("Sending get request to the enclave");
    return allowAllCerts
      .get("https://enclave.localhost:443/egress", {
        headers: { "api-key": "placeholder" },
      })
      .then((result) => {
        expect(result.data).to.deep.equal({
          userId: 1,
          id: 1,
          title:
            "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
          body: "quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto",
        });
      })
      .catch((err) => {
        console.error(err);
        throw err;
      });
  });

  it("calls out to the internet for banned domain", () => {
    console.log("Sending get request to the enclave");
    return allowAllCerts
      .get("https://enclave.localhost:443/egressBanned", {
        headers: { "api-key": "placeholder" },
      })
      .then((result) => {
        throw Error("Egress request should have failed for banned domain");
      })
      .catch((err) => {
        expect(err.response.data.message).to.deep.equal(
          "getaddrinfo EAI_AGAIN evervault.com"
        );
      });
  });

  it("encrypts and decrypt via E3", async () => {
    const data = { test: "test", number: 123, bool: true };
    // test full cycle crypto in the customer process
    const {
      data: { decrypted },
    } = await allowAllCerts.post("https://enclave.localhost:443/crypto", data, {
      headers: { "api-key": "placeholder" },
    });
    expect(data).to.deep.equal(decrypted);
  });

  it("decrypts the request as it enters the enclave", async () => {
    const data = {
      test: "test",
      number: 123,
      bool: true,
      obj: { nested: "yes" },
      arr: [456],
    };
    // test data plane stream decryption
    const encryptResult = await allowAllCerts.post(
      "https://enclave.localhost:443/encrypt",
      data,
      { headers: { "api-key": "placeholder" } }
    );
    const decryptResult = await allowAllCerts.post(
      "https://enclave.localhost:443/hello",
      encryptResult.data,
      { headers: { "api-key": "placeholder" } }
    );
    const { response, ...echoPayload } = decryptResult.data;
    expect(echoPayload).to.deep.equal(data);
  });

  it("returns the injected environment", async () => {
    const result = await allowAllCerts.get("https://enclave.localhost:443/env", {
      headers: { "api-key": "placeholder" },
    });
    expect("123").to.deep.equal(result.data.ANOTHER_ENV_VAR);
  });

  it("attestation doc", async () => {
    const doc = await allowAllCerts
      .post(
        "https://enclave.localhost:443/attestation-doc",
        {},
        { headers: { "api-key": "placeholder" }, responseType: "arraybuffer" }
      )
      .catch((err) => {
        console.error(err);
        throw err;
      });
    const result = CBOR.decode(doc.data);
    expect(result).to.deep.equal({
        pcr0: "000",
        pcr1: "000",
        pcr2: "000",
        pcr8: "000",
    });
  });

  it("enclave responds and echos back body without transfer-encoding", () => {
    return allowAllCerts
      .post(
        "https://enclave.localhost:443/chunked",
        { secret: "ev:123" },
        { headers: { "api-key": "placeholder" } }
      )
      .then((result) => {
        console.log("Post request sent to the enclave");
        expect(result.data).to.deep.equal({
          response: "Hello from enclave",
          secret: "ev:123",
        });
        //check transfer-encoding is not set
        expect(result.headers['transfer-encoding']).to.be.undefined;
      })
      .catch((err) => {
        console.error(err);
        throw err;
      });
  });
});

describe("Enclave is runnning", () => {
  // Statsd tests are async and wait for data to be published by the Cage. Adding done callback to prevent early exit.
  it("system metrics are sent to statsD", (done) => {
    const sysClient = new net.Socket();
    sysClient.connect(8126, "127.0.0.1", function () {
      sysClient.write("gauges");
    });

    sysClient.on("data", function (data) {
      try {
        const result = data.toString().replace(/'/g, '"').replace(/END/g, "");
        console.log("[SYSTEM]", result);
        const stats = JSON.parse(result);
        const keys = Object.keys(stats);
        expect(keys).to.include(
          "evervault.enclaves.memory.total;enclave_uuid=enclave_123;app_uuid=app_12345678"
        );
        expect(keys).to.include(
          "evervault.enclaves.memory.avail;enclave_uuid=enclave_123;app_uuid=app_12345678"
        );
        expect(keys).to.include(
          "evervault.enclaves.cpu.one;enclave_uuid=enclave_123;app_uuid=app_12345678"
        );
        expect(keys).to.include(
          "evervault.enclaves.cpu.cores;enclave_uuid=enclave_123;app_uuid=app_12345678"
        );
      } finally {
        sysClient.destroy();
        done();
      }
    });
  });

  it("product metrics are sent to statsD", (done) => {
    const prodClient = new net.Socket();
    prodClient.connect(8126, "127.0.0.1", function () {
      prodClient.write("counters");
    });

    prodClient.on("data", function (data) {
      try {
        const result = data.toString().replace(/'/g, '"').replace(/END/g, "");
        console.log("[PRODUCT]", result);
        const stats = JSON.parse(result);
        const keys = Object.keys(stats);

        expect(keys).to.include(
          "evervault.enclaves.decrypt.count;enclave_uuid=enclave_123;app_uuid=app_12345678"
        );
      } finally {
        prodClient.destroy();
        done();
      }
    });
  });
});