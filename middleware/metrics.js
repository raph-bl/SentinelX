const client = require('prom-client');
const register = new client.Registry();

client.collectDefaultMetrics({ register });

const httpRequests = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'endpoint', 'status_code'],
    registers: [register],
});

module.exports = { register, httpRequests };