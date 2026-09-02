const { expect } = require('chai');
const axios = require('axios').default;

describe('GET env from enclave', () => {
    it('returns the injected environment var', async () => {
        const result =  await axios.get('http://enclave.localhost:443/env', { headers: { 'api-key': 'placeholder' } })
        expect("123").to.deep.equal(result.data.ANOTHER_ENV_VAR)
    });
});