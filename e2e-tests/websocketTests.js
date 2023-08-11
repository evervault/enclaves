const { expect } = require('chai');
const assert = require('assert');
const WebSocket = require('ws');

describe('Make websocket request', () => {

    it('should start websocket session', async () => {
        const options = {
            rejectUnauthorized: false,
            headers: {
                'api-key':'placeholder'
            }
        };

        const serverUrl = 'wss://localhost:443/hello';

        const socket = new WebSocket(serverUrl, options);

        socket.on('open', () => {
            console.log('Connected to WebSocket server');
            socket.send('test connection');
        });
        
        socket.on('message', (data) => {
            console.log('Received message from server:', data.toString('utf8'));
            expect(data.toString('utf8')).to.equal("SERVER RECIEVED MESSAGE: test connection");
            socket.close()
        });
        
    })

    it('should start websocket session', async () => {
        const options = {
            rejectUnauthorized: false
        };

        const serverUrl = 'wss://localhost:443/hello';

        const socket = new WebSocket(serverUrl, options);

        socket.on('open', () => {
            console.log('Connected to WebSocket server');
            socket.send('test connection');
        });

        socket.on('error', (err) => {
            expect(err.message).to.equal("Unexpected server response: 401");
        });  

        socket.on('message', (data) => {
            assert.fail('Connection was sucessful, 401 expected');
        });
    })

});