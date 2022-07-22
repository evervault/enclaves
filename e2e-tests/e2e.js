const { expect } = require('chai');
const axios = require('axios').default;

describe('POST data to enclave', () => {
    it('enclave responds and echos back body', async () => {
        const result = await axios.post('http://0.0.0.0:3030/hello', { secret: 'ev:123' })
        expect(result.data).to.deep.equal({ response: 'Hello from enclave',  secret: 'ev:123'});
    });

    it('calls out to the internet', async () => {
        const result = await axios.get('http://localhost:3030/egress')
        expect(result.data).to.deep.equal({
            userId :1,
            id:1,
            title:"sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
            body :"quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto"});
    });
});