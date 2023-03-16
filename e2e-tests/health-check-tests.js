const { expect } = require('chai');
const { spawn } = require('child_process');

describe('Run health-check request', () => {

    const runHealthCheckScript = async () => {
        const cmd = spawn('sh', ['../scripts/health-check.sh']);
        return await new Promise((resolve) => cmd.on('exit', code => {
            resolve(code)
        }));
    };

    it('should output success exit code', async () => {
        const exitCode = await runHealthCheckScript();
        expect(exitCode).to.equal(0);
    });

    it('should fail with non-zero exit code', async () => {
        const exitCode = await runHealthCheckScript();
        expect(exitCode).to.not.equal(0);
    });
});