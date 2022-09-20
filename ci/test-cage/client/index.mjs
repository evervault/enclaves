import phin from 'phin';
import assert from 'node:assert/strict';

const { 
    CAGE_NAME,  
    APP_UUID,
    ENVIRONMENT,
    EV_API_KEY
} = process.env;

const hostname = ENVIRONMENT === 'staging' ? 'cages.evervault.dev' : 'cages.evervault.com';

async function testCageInvocation() {
    const requestBody = {
        hello: "world",
        array: [{
            result: true
        }]
    };
    
    const response = await phin({
        url: `https://${CAGE_NAME}.${APP_UUID}.${hostname}/echo`,
        method: 'POST',
        headers: {
            'API-KEY': EV_API_KEY,
            'content-type': 'application/json'
        },
        data: requestBody
    });

    const responseBody = JSON.parse(response.body.toString());
    assert.deepEqual(requestBody, responseBody.body);
}

async function testCageCrypto() {
    const requestBody = {
        hello: "world"
    };
    
    const response = await phin({
        url: `https://${CAGE_NAME}.${APP_UUID}.${hostname}/crypto`,
        method: 'POST',
        headers: {
            'API-KEY': EV_API_KEY,
            'content-type': 'application/json'
        },
        data: requestBody
    });

    const {
        encrypted,
        decrypted
    } = JSON.parse(response.body.toString());
    assert.notDeepEqual(requestBody, encrypted.parsed);
    assert.deepEqual(requestBody, decrypted.parsed);

    // TODO: Add step for encrypted payload decryption via outbound
}

async function testCageEgress() {
    const response = await phin({
        url: `https://${CAGE_NAME}.${APP_UUID}.${hostname}/egress`,
        headers: {
            'API-KEY': EV_API_KEY,
        }
    });

    const {
        code,
        externalResponse
    } = JSON.parse(response.body.toString());
    console.log({ externalResponse });
    assert.deepEqual(code, 'egress-complete');
}

async function testCageAttest() {
    const requestBody = {
        nonce: "test-nonce",
        challenge: "test-challenge",
    };
    
    const response = await phin({
        url: `https://${CAGE_NAME}.${APP_UUID}.${hostname}/attest`,
        method: 'POST',
        headers: {
            'API-KEY': EV_API_KEY,
            'content-type': 'application/json'
        },
        data: requestBody
    });
    const responseBody = JSON.parse(response.body.toString());
    assert.deepEqual(responseBody.code, 'attest-complete');
}

Promise.all([
    testCageInvocation(),
    testCageCrypto(),
    testCageEgress(),
    testCageAttest()
]).then(() => {
    console.log('Tests passed');
}).catch((err) => {
    console.error('Tests failed', {
        err
    });
    process.exit(1);
});