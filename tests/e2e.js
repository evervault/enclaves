const { expect } = require('chai');
const axios = require('axios').default;

describe('POST data to enclave', () => {
    it('enclave responds and echos back body', async () => {
        const result = await axios.post('http://localhost:3030/hello', { secret: 'ev:123' })
        expect(result.data).to.deep.equal({ response: 'Hello from enclave',  secret: 'ev:123'});
 });
});