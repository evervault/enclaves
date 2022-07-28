const { expect } = require('chai');
const axios = require('axios').default;
const https = require('https');

describe('POST data to enclave', () => {
    const allowAllCerts = axios.create({
        httpsAgent: new https.Agent({
            rejectUnauthorized: false
        })
    });
    it('enclave responds and echos back body', () => {
        console.log('Sending post request to enclave');
        return allowAllCerts.post('https://localhost:443/hello',{ secret: 'ev:123' }, { headers: { 'api-key': 'placeholder' } }).then((result) => {
            console.log('Post request sent to the enclave');
            expect(result.data).to.deep.equal({ response: 'Hello from enclave',  secret: 'ev:123'});
        });
    });

    it('calls out to the internet', () => {
        console.log('Sending get request to the enclave');
        return allowAllCerts.get('https://localhost:443/egress', { headers: { 'api-key': 'placeholder' } }).then((result) => {
            console.log('Get request sent to the enclave');
            expect(result.data).to.deep.equal({
                userId :1,
                id:1,
                title:"sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
                body :"quia et suscipit\nsuscipit recusandae consequuntur expedita et cum\nreprehenderit molestiae ut ut quas totam\nnostrum rerum est autem sunt rem eveniet architecto"});
        });
    });
});