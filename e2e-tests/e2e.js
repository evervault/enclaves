const { expect } = require('chai');
const axios = require('axios').default;
const https = require('https');
const CBOR = require('cbor-sync')

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