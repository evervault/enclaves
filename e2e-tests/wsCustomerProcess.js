const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8008 });


wss.on('connection', (ws) => {
    ws.on('message', (messageAsString) => { 
        ws.send("SERVER RECIEVED MESSAGE: " + messageAsString);
    })
})