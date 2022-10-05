const chai = require('chai');
chai.use(require('chai-http'));
const { expect, request } = chai;

describe('Run health-check request', () => {
    it('should succeed', async () => {
        const result =  await request('http://localhost:3032').get('/').set('User-Agent', 'ECS-HealthCheck');
        expect(result).to.have.status(200);
    });

    it('should fail', async () => {
        const result =  await request('http://localhost:3032').get('/').set('User-Agent', 'ECS-HealthCheck');
        expect(result).to.have.status(500);
    });
});