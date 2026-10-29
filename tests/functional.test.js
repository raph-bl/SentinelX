const { test } = require('node:test')
const assert = require('node:assert')
const request = require('supertest')
const app = require('../app')

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
