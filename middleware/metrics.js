const client = require('prom-client');
const register = new client.Registry();

client.collectDefaultMetrics({ register });

const httpDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP reqs in seconds',
    labelNames: ['method', 'route'],
    buckets: [0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],   // valeurs §5
    registers: [register],
})

const appEvents = new client.Counter({
    name: 'app_events_total',
    help: 'Application events',
    labelNames: ['event_type'],
    registers: [register]
})

const httpRequests = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code'],
    registers: [register],
});

module.exports = { register, httpRequests, httpDuration, appEvents };