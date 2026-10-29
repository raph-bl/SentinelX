const { test } = require('node:test')
const assert = require('node:assert')
const request = require('supertest')
const app = require('../app')

// A RELIRE
// Capture les lignes de log JSON émises par le logger sur stdout pendant `fn`.
// On enveloppe process.stdout.write (sans casser la sortie TAP du runner) et on
// parse les lignes qui ressemblent à un event. setTimeout laisse le temps au
// handler res.on('finish') de s'exécuter après la fin de la requête.
async function captureLogs(fn) {
    const lines = []
    const orig = process.stdout.write
    process.stdout.write = function (chunk) {
        const s = typeof chunk === 'string' ? chunk : chunk.toString()
        s.split('\n').forEach((l) => {
            if (l.includes('"event_type"')) {
                try { lines.push(JSON.parse(l)) } catch { /* ligne non-JSON, ignorée */ }
            }
        })
        return orig.apply(process.stdout, arguments)
    }
    try {
        await fn()
        await new Promise((r) => setTimeout(r, 20))
    } finally {
        process.stdout.write = orig
    }
    return lines
}

test('POST /login with valid creds should redirect to /dashboard', async() => {
    const res = await request(app)
        .post('/login')
        .type('form')
        .send({ email: 'admin@supportdesk.local', password: 'Admin_123'})

    assert.strictEqual(res.status, 302)
    assert.strictEqual(res.headers.location, '/dashboard')
})

test('POST /login with invalid creds should redirect to /login?error=1', async() => {
    const res = await request(app)
        .post('/login')
        .type('form')
        .send({ email: 'admin@supportdesk.local', password: 'wrongpassword'})

    assert.strictEqual(res.status, 302)
    assert.match(res.headers.location, /\/login\?error=1/)
})

// access control

test('GET /dashboard without login should redirect to /login', async() => {
    const res = await request(app)
        .get('/dashboard')
    
    assert.strictEqual(res.status, 302)
    assert.strictEqual(res.headers.location, '/login')
})

test('GET /kb/view?doc=inexistant should return 404', async() => {
    // But first we connect
    const agent = request.agent(app)

    await agent.post('/login')
        .type('form')
        .send({ email: 'jdupont@supportdesk.local', password: 'User_123'})

    const res = await agent.get('/kb/view?doc=inexistant')
    assert.strictEqual(res.status, 404)
})

// observabilité

test('GET /metrics should return prometheus metrics', async() => {
    const res = await request(app).get('/metrics')
    assert.strictEqual(res.status, 200)
    assert.match(res.headers['content-type'], /text\/plain/)
    assert.match(res.text, /http_requests_total/)        // la métrique du contrat §5
})

// contrôle d'accès admin

test('GET /admin as non-admin should return 403', async() => {
    const agent = request.agent(app)
    await agent.post('/login')
        .type('form')
        .send({ email: 'jdupont@supportdesk.local', password: 'User_123'})   // role = user

    const res = await agent.get('/admin')
    assert.strictEqual(res.status, 403)
})

// contenu des logs : distinction auth_failure / auth_success

test('a failed login emits an auth_failure WARN log', async() => {
    const logs = await captureLogs(() =>
        request(app).post('/login')
            .type('form')
            .send({ email: 'admin@supportdesk.local', password: 'wrongpassword'}))

    const line = logs.find((l) => l.endpoint === '/login' && l.method === 'POST')
    assert.ok(line, 'une ligne de log /login doit être émise')
    assert.strictEqual(line.event_type, 'auth_failure')
    assert.strictEqual(line.level, 'WARN')
})

test('a successful login emits an auth_success INFO log', async() => {
    const logs = await captureLogs(() =>
        request(app).post('/login')
            .type('form')
            .send({ email: 'admin@supportdesk.local', password: 'Admin_123'}))

    const line = logs.find((l) => l.endpoint === '/login' && l.method === 'POST')
    assert.ok(line, 'une ligne de log /login doit être émise')
    assert.strictEqual(line.event_type, 'auth_success')
    assert.strictEqual(line.level, 'INFO')
})
