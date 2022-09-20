import Fastify from 'fastify';
import phin from 'phin';

const fastify = Fastify({
    logger: true
});

function tryHandleRequest(endpointHandler) {
    return async function (request, reply) {
        try {
            await endpointHandler(request, reply);
        } catch (err) {
            console.error('Error handling request', {
                err
            });
            reply.send({
                error: err,
                message: 'An error was thrown by the endpoint handler'
            });
        }
    }
}

fastify.all('/echo', tryHandleRequest((request, reply) => {
    console.log('Echo request received');
    reply.send({
        body: request.body,
        headers: request.headers
    });
}));

fastify.post('/crypto', tryHandleRequest(async (request, reply) => {
    const encryptedPayload = await phin({
        url: 'http://127.0.0.1:9999/encrypt',
        data: request.body,
        headers: {
            'Content-Type': 'application/json',
            'Api-Key': process.env.EV_API_KEY
        },
        method: 'POST'
    });

    console.log('Response received from encryption api', {
        payload: encryptedPayload.body.toString(),
        receivedBody: request.body
    });

    const decryptedPayload = await phin({
        url: 'http://127.0.0.1:9999/decrypt',
        data: JSON.parse(encryptedPayload.body.toString()),
        headers: {
            'Content-Type': 'application/json',
            'Api-Key': process.env.EV_API_KEY
        },
        method: 'POST'
    });

    const encryptedPayloadString = encryptedPayload.body.toString();
    const decryptedPayloadString = decryptedPayload.body.toString();

    reply.send({ 
        message: 'Crypto ops complete', 
        encrypted: { string: encryptedPayloadString, parsed: JSON.parse(encryptedPayloadString) },
        decrypted: { string: decryptedPayloadString, parsed: JSON.parse(decryptedPayloadString) },
    });
}));

fastify.get('/egress', tryHandleRequest(async (_, reply) => {
    const loremIpsumResponse = await phin({
        url: 'https://baconipsum.com/api/?type=meat-and-filler'
    });

    reply.send({
        message: 'Egress request completed successfully',
        code: 'egress-complete',
        externalResponse: JSON.parse(loremIpsumResponse.body.toString())
    });
}));

fastify.post('/attest', tryHandleRequest(async (request, reply) => {
    const attestationDoc = await phin({
        url: 'http://127.0.0.1:9999/attestation-doc',
        data: request.body,
        headers: {
            'Content-Type': 'application/json'
        },
        method: 'POST'
    });

    reply.send({
        message: 'Obtained attestation doc',
        code: 'attest-complete',
        attestationDocumentResponse: attestationDoc.body.toString()
    });
}));

fastify.listen({ port: 3000 }, (err) => {
    if(err) {
        console.error('Error starting server', {
            err
        });
        throw err;
    }
});