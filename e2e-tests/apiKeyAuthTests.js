const { expect } = require('chai');
const axios = require('axios').default;
const https = require('https');

describe('POST data to enclave with api key auth enabled', async () => {
    const allowAllCerts = axios.create({
        httpsAgent: new https.Agent({
            rejectUnauthorized: false
        })
    });
    context('Valid api key is sent as header', () => {
        it('returns successfully', async () => {
            let result = await allowAllCerts.post('https://enclave.localhost:443/hello', { secret: 'ev:123' }, { headers: { 'api-key': 'placeholder' } })
            expect(result.data).to.deep.equal({ response: 'Hello from enclave', secret: 'ev:123' });
        });
    });

    context('Invalid api key is sent as header', () => {
        it('returns 401', async () => {
            try {
                let result = await allowAllCerts.post('https://enclave.localhost:443/hello', { secret: 'ev:123' }, { headers: { 'api-key': 'invalid' } })
                expect(result.status).to.not.equal(200)
            } catch (err) {
                expect(err.response.status).to.equal(401);
            }
        });
    });

    context('No api key is sent as header', () => {
        it('returns 401', async () => {
            try {
                let result = await allowAllCerts.post('https://enclave.localhost:443/hello', { secret: 'ev:123' })
                expect(result.status).to.not.equal(200)
            } catch (err) {
                expect(err.response.status).to.equal(401);
            }
        });
    });
});