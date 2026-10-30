// Logging middleware -- makes SupportDesk observable.
//
// Mounted in app.js AFTER session + express.urlencoded, BEFORE the routers:
//   app.use(require('./middleware/logger'))
//
// Emits ONE JSON line per request on stdout, following the schema in CONTRACT.md.
// The event is built on response 'finish' so status_code, duration and the
// redirect target (Location header) are known.

// Paths we never log: Prometheus scrape, static assets and browser source maps.
// This keeps the signal clean for the false-positive measurement (see CONTRACT.md).
const { httpRequests, httpDuration, appEvents } = require('./metrics');
const path = require('path')
const IGNORED = [/^\/metrics\b/, /^\/bootstrap\//, /\.map$/]
const fs = require('fs')
const LOG_FILE = process.env.LOG_FILE || '/var/log/supportdesk/app.log'
const LOG_BODY_MAX = parseInt(process.env.LOG_BODY_MAX, 10) || 1024
const truncate = (s) => (s.length > LOG_BODY_MAX ? s.slice(0, LOG_BODY_MAX) : s)
const folder = path.dirname(LOG_FILE)
fs.mkdirSync(folder, { recursive: true })

function logger(req, res, next) {
  const startedAt = process.hrtime.bigint()
  // Capture the full path NOW: req.path/req.url get stripped of the router mount
  // prefix (e.g. '/tickets') by the time the 'finish' event fires. originalUrl
  // is never modified by routers.
  const endpoint = req.originalUrl.split('?')[0]

  if (IGNORED.some((re) => re.test(endpoint))) return next()

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
    const { event_type, level, message } = classify(req, res, endpoint)
    const route = routePattern(endpoint)

    // CONTRACT §3.1: flat object, strings only. §4.2: query/body logged RAW (no
    // decoding) so attack patterns stay visible, then truncated to LOG_BODY_MAX.
    const rawQuery = req.originalUrl.split('?')[1] || ''   // raw query string, not decoded
    const bodyStr = req.body && Object.keys(req.body).length
      ? JSON.stringify(redact(req.body))                   // password masked before logging
      : ''
    const userAgent = req.get('user-agent')

    const event = {
      timestamp: new Date().toISOString(),
      level,
      event_type,
      source_ip: normalizeIp(req.ip),          // needs app.set('trust proxy', true)
      user: (req.session && req.session.username) || null,
      endpoint,                                // full path captured at entry
      method: req.method,
      status_code: res.statusCode,
      message,
      response_time_ms: Math.round(durationMs)
    }
    // Non-applicable fields are omitted (CONTRACT §3.1), except user (kept null above).
    if (rawQuery) event.query = truncate(rawQuery)         // SQLi / traversal payloads land here
    if (bodyStr) event.body = truncate(bodyStr)
    if (userAgent) event.user_agent = userAgent

    httpRequests.inc({ method: req.method, route, status_code: res.statusCode })
    
    //!\\ a relire 
    httpDuration.observe({ method: req.method, route}, durationMs / 1000)
    appEvents.inc({ event_type })
    
    process.stdout.write(JSON.stringify(event) + '\n')
    fs.appendFileSync(LOG_FILE, JSON.stringify(event) + '\n')
  })

  next()
}

function classify(req, res, endpoint) {
  const user = (req.session && req.session.username) || 'anonymous'

  // Server errors take priority over whatever endpoint was hit.
  if (res.statusCode >= 500) {
    return { event_type: 'server_error', level: 'ERROR', message: `Server error on ${endpoint}` }
  }

  /*** 
   * Authentification
  ***/
  if (req.method === 'POST' && endpoint === '/login') {
    const location = res.getHeader('Location') || ''
    // Both outcomes return 302; only the redirect target distinguishes them.
    if (location.includes('/login')) {
      return {
        event_type: 'auth_failure',
        level: 'WARN',
        message: `Failed login for ${(req.body && req.body.email) || 'unknown'}`
      }
    }
    return {
      event_type: 'auth_success',
      level: 'INFO',
      message: `Successful login for ${(req.body && req.body.email) || 'unknown'}`
    }
  }

  if (req.method === 'GET' && endpoint === '/logout') {
    return { event_type: 'logout', level: 'INFO', message: `User ${user} logged out` }
  }

  // Access denied: explicit 403 (isAdmin), OR a 302 redirect to /login on a protected
  // route (isAuthenticated bounced an unauthenticated request). CONTRACT §3.2 row 5.
  // Placed before the endpoint-specific branches so a 403 on /admin is not logged as admin_view.
  const location = res.getHeader('Location') || ''
  const protectedPath = !['/', '/login', '/logout'].includes(endpoint)
  if (res.statusCode === 403 ||
      (res.statusCode === 302 && String(location).includes('/login') && protectedPath)) {
    return {
      event_type: 'access_denied',
      level: 'WARN',
      message: res.statusCode === 403 ? `Forbidden for ${user} on ${endpoint}` : `Unauthenticated access to ${endpoint}`
    }
  }

  /***
   * Tickets
   ***/
  if (req.method === 'GET' && endpoint === '/tickets') {
    return { event_type: 'ticket_list', level: 'INFO', message: `User ${user} listed tickets` }
  }

  if (req.method === 'POST' && endpoint === '/tickets/search') {
    return { event_type: 'ticket_search', level: 'INFO', message: `User ${user} searched tickets` }
  }

  // Export has no ownership check (IDOR). Logging requester + ticket id lets a
  // Wazuh rule flag a user exporting tickets in bulk / not their own.
  const exportMatch = endpoint.match(/^\/tickets\/(\d+)\/export$/)
  if (req.method === 'GET' && exportMatch) {
    return {
      event_type: 'ticket_export',
      level: 'INFO',
      message: `User ${user} exported ticket #${exportMatch[1]}`
    }
  }

  const commentMatch = endpoint.match(/^\/tickets\/(\d+)\/comment$/)
  if (req.method === 'POST' && commentMatch) {
    return {
      event_type: 'ticket_comment',
      level: 'INFO',
      message: `User ${user} commented on ticket #${commentMatch[1]}`
    }
  }

  const viewMatch = endpoint.match(/^\/tickets\/(\d+)$/)
  if (req.method === 'GET' && viewMatch) {
    return {
      event_type: 'ticket_view',
      level: 'INFO',
      message: `User ${user} viewed ticket #${viewMatch[1]}`
    }
  }

  // Knowledge base -- only a real view (200). A 404 falls through to not_found below.
  if (req.method === 'GET' && endpoint === '/kb/view' && res.statusCode === 200) {
    return { event_type: 'kb_view', level: 'INFO', message: `User ${user} opened a KB document` }
  }

  /***
   * Admin
   ***/
  // Server-side fetch of an arbitrary URL (SSRF surface).
  if (req.method === 'POST' && endpoint === '/admin/fetch') {
    return { event_type: 'admin_fetch', level: 'WARN', message: `User ${user} triggered admin fetch` }
  }

  if (req.method === 'GET' && endpoint === '/admin') {
    return { event_type: 'admin_view', level: 'INFO', message: `User ${user} opened admin panel` }
  }

  /***
   * Profile 
   ***/  
  if (req.method === 'POST' && endpoint === '/profile') {
    return { event_type: 'profile_update', level: 'INFO', message: `User ${user} updated profile` }
  }

  // Not found (CONTRACT §3.2 row 13): any remaining 404, incl. /kb/view of a missing doc.
  if (res.statusCode === 404) {
    return { event_type: 'not_found', level: 'WARN', message: `Not found: ${endpoint}` }
  }

  /***
   * Default
   ***/
  const level = res.statusCode >= 400 ? 'WARN' : 'INFO'
  return { event_type: 'http_request', level, message: 'HTTP request' }
}

// Mask sensitive fields before they hit the logs. Returns a shallow copy so the
// original request body is left untouched.
function redact(body) {
  if (!body || typeof body !== 'object') return body
  const clone = { ...body }
  if ('password' in clone) clone.password = '***'
  return clone
}

// TODO: à relire
function routePattern(endpoint) {
  if (endpoint === '/') return '/'

    return endpoint
      .replace(/^\/tickets\/\d+\/export$/, '/tickets/:id/export')
      .replace(/^\/tickets\/\d+\/comment$/, '/tickets/:id/comment')
      .replace(/^\/tickets\/\d+$/, '/tickets/:id')
}

// Docker gives IPv4-mapped IPv6 addresses like '::ffff:192.168.65.1'. Strip the
// prefix so source_ip is a plain IPv4 that correlation rules can group on.
function normalizeIp(ip) {
  if (typeof ip === 'string' && ip.startsWith('::ffff:')) return ip.slice(7)
  return ip
}

module.exports = logger
