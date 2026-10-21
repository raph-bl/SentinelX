// Logging middleware -- makes SupportDesk observable.
//
// Mount in app.js AFTER session + express.urlencoded, BEFORE the routers:
//   app.use(require('./middleware/logger'))
//
// Emits ONE JSON line per request on stdout, following the schema in CONTRACT.md.
// The event is built on response 'finish' so status_code, duration and the
// redirect target are known.

function logger (req, res, next) {
  const startedAt = process.hrtime.bigint()
  // Capture the full path NOW: req.path/req.url get stripped of the router mount
  // prefix (e.g. '/tickets') by the time the 'finish' event fires. originalUrl
  // is never modified by routers.
  const endpoint = req.originalUrl.split('?')[0]

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6

    // --- classify the business event ----------------------------------------
      // TODO: decide the event_type from (method, path, status, redirect target).
    //       Hard cases to handle here (see the route comments):
    //         - auth_failure vs auth_success: login always returns 302, so you
    //           must read res.getHeader('Location') (/login?error=1 vs /dashboard).
    //         - ticket_export (IDOR): /tickets/:id/export returns 200; to be
    //           detectable it needs requester identity + ticket owner together.
    //         - server_error: status >= 500 (coordinate with the global handler).
    const { event_type, level, message } = classify(req, res, endpoint)

    const event = {
      timestamp: new Date().toISOString(),
      level,                                   // TODO: derive INFO / WARN / ERROR
      event_type,
      source_ip: req.ip,                       // needs app.set('trust proxy', true)
      user: (req.session && req.session.username) || null,
      endpoint,                                // full path captured at entry
      method: req.method,
      status_code: res.statusCode,
      message,
      query: req.query,                        // keep: SQLi / traversal payloads land here
      body: redact(req.body),                  // TODO: mask password before logging
      duration_ms: Math.round(durationMs)      // optional, useful for /metrics too
    }

    process.stdout.write(JSON.stringify(event) + '\n')
  })

  next()
}

// Map the request to a business event. Returns { event_type, level, message }.
// TODO: implement the real logic + a sane default (e.g. http_request / INFO).
function classify (req, res, endpoint) {
  if (req.method === 'POST' && endpoint === '/login') {
    const location = res.getHeader('Location') || ''
    if (location.includes('/login')) {
      return {
        event_type: 'auth_failure',
        level: 'WARN',
        message: `Failed login for ${req.body.email || 'unknown'}`
      }
    }
    return {
      event_type: 'auth_success',
      level: 'INFO',
      message: `Successful login for ${req.body.email || 'unknown'}`
    }
  }

  if (req.method === 'GET' && endpoint === '/logout') {
    return {
      event_type: 'auth_logout',
      level: 'INFO',
      message: `User ${req.session.username || 'unknown'} logged out`
    }
  }

  if (req.method === 'GET' && endpoint === '/tickets') {
    return {
      event_type: 'ticket_list',
      level: 'INFO',
      message: `User ${req.session.username || 'unknown'} listed tickets`
    }
  }

  if (req.method === 'POST' && endpoint === '/tickets/search') {
    return {
      event_type: 'ticket_search',
      level: 'INFO',
      message: `User ${req.session.username || 'unknown'} searched tickets`
    }
  }

  return { event_type: 'http_request', level: 'INFO', message: '' }
}

// Remove or mask sensitive fields before they hit the logs.
// TODO: at minimum redact body.password; decide on truncation / allow-list.
function redact (body) {
  return body
}

module.exports = logger
