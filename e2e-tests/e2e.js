const { expect } = require('chai');
const axios = require('axios').default;
const https = require('https');
const CBOR = require('cbor-sync');

describe('POST data to enclave', () => {
    const allowAllCerts = axios.create({
        httpsAgent: new https.Agent({
            rejectUnauthorized: false
        })
    });
    it('enclave responds and echos back body', () => {
        console.log('Sending post request to enclave');
        return allowAllCerts.post('https://cage.localhost:443/hello',{ secret: 'ev:123' }, { headers: { 'api-key': 'placeholder' } }).then((result) => {
            console.log('Post request sent to the enclave');
            expect(result.data).to.deep.equal({ response: 'Hello from enclave',  secret: 'ev:123'});
        }).catch((err) => {
          console.error(err);
          throw err;
        });
    });

    it('calls out to the internet', () => {
        console.log('Sending get request to the enclave');
        return allowAllCerts.get('https://cage.localhost:443/egress', { headers: { 'api-key': 'placeholder' } }).then((result) => {
            console.log('Get request sent to the enclave');
            expect(result.data).to.deep.equal({
                userId :1,
                id:1,
                title:"sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
                body :"quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto"});
        }).catch((err) => {
          console.error(err);
          throw err;
        });
    });

    it('encrypts and decrypt via E3', async () => {
        const data = { test: "test", number: 123, bool: true }
        // test full cycle crypto in the customer process
        const { data: { decrypted } } =  await allowAllCerts.post('https://cage.localhost:443/crypto', data, { headers: { 'api-key': 'placeholder' } })
        expect(data).to.deep.equal(decrypted)
    });

    it('decrypts the request as it enters the enclave', async () => {
      const data = { test: "test", number: 123, bool: true, obj: { nested: "yes" }, arr: [456] }
      // test data plane stream decryption
      const encryptResult =  await allowAllCerts.post('https://cage.localhost:443/encrypt', data, { headers: { 'api-key': 'placeholder' } })
      const decryptResult = await allowAllCerts.post('https://cage.localhost:443/hello', encryptResult.data, { headers: { 'api-key': 'placeholder' } });
      const { response, ...echoPayload } = decryptResult.data;
      expect(data).to.deep.equal(echoPayload)
    });

    it('returns the injected environment', async () => {
        const result =  await allowAllCerts.get('https://cage.localhost:443/env', { headers: { 'api-key': 'placeholder' } })
        expect("123").to.deep.equal(result.data.ANOTHER_ENV_VAR)
    });

    it('attestation doc', async () => {
        const doc =  await allowAllCerts.post('https://cage.localhost:443/attestation-doc', {}, { headers: { 'api-key': 'placeholder' }, responseType: "arraybuffer" }).catch((err) => {
          console.error(err);
          throw err;
        })
        const result = CBOR.decode(doc.data);
        expect(result).to.deep.equal({
            "Measurements": {
                "PCR0": "000",
                "PCR1": "000", 
                "PCR2": "000",
                "PCR8": "000"
            }
        })
    });

});



describe('Enclave is runnning', () => {
    it('system metrics are sent to statsD', () => {
        var net = require('net');

        var client = new net.Socket();
        client.connect(8126, '127.0.0.1', function() {
            client.write('gauges');
        });

        client.on('data', function(data) {
            let result = data.toString().replace(/'/g, '"').replace(/END/g, '');
            let stats = JSON.parse(result);
            let keys = Object.keys(stats);
            expect(keys).to.include('memory.total;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('memory.avail;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('memory.free;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('cpu.one;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('cpu.five;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('cpu.fifteen;cage_uuid=cage_123;app_uuid=app_12345678');
            expect(keys).to.include('cpu.cores;cage_uuid=cage_123;app_uuid=app_12345678');
            client.destroy();
        });
    });

    it('product metrics are sent to statsD', () => {
        var net = require('net');

        var client = new net.Socket();
        client.connect(8126, '127.0.0.1', function() {
            client.write('counters');
        });

        client.on('data', function(data) {
            let result = data.toString().replace(/'/g, '"').replace(/END/g, '');
            let stats = JSON.parse(result);
            let keys = Object.keys(stats);
            expect(keys).to.include('decrypt.count;cage_uuid=cage_123;app_uuid=app_12345678');
            client.destroy();
        });
    });
});