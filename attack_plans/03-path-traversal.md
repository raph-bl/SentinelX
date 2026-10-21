## Attack Plan -- Path traversal on the knowledge base viewer

### Rules of engagement
Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Additional constraints specific to this scenario:
- Read-only exploitation: files are read, never modified or deleted.
- Do not exfiltrate real secrets outside the lab; reading `supportdesk.db` and the seed file
  is in scope only to prove impact, and their contents stay on the local host.
- Run from a single, fixed source IP sent via the `X-Forwarded-For` header so `source_ip`
  is deterministic and not the Docker bridge address.
- A valid authenticated session is required (the route sits behind `isAuthenticated`);
  use the seeded `jdupont@supportdesk.local` account.
- Stop the realistic traffic script before launch so the traversal burst is isolated.

### Scope
Endpoints within the attack perimeter:
- `GET /kb/view` -- injectable query parameter: `doc`
  (concatenated into a filesystem path via `path.join(..., 'public', 'kb', doc)` and read with
  `fs.readFileSync`, with no normalization or containment check -- `routes/kb.js`)

Out of scope: all other endpoints, write/delete operations on the filesystem, and the host
OS outside the application container.

### Attack vectors
- Relative path traversal via `doc` to escape the `public/kb` directory and read arbitrary
  files inside the container, e.g.:
  - `?doc=../../app.js` -- application source code disclosure
  - `?doc=../../database/seed.js` -- seeded credentials disclosure
  - `?doc=../../supportdesk.db` -- raw SQLite database (users, tickets, comments)
  - `?doc=../../../../etc/passwd` -- OS file read, proves full containment escape
- URL-encoded traversal variants to probe for naive filters: `%2e%2e%2f`, `..%2f`, `....//`.

Note: a successful read returns HTTP 200 with file contents; a miss returns 404. Detection
must inspect the `endpoint`/`query` fields (traversal sequences), not the HTTP status alone.

### Tools used
- `curl` (primary -- direct requests with `--cookie` for the session, encoded payload variants)
- `ffuf` (optional -- fuzz the `doc` parameter with a traversal/LFI wordlist)
- Browser (manual confirmation that file contents render in the viewer)

### Success criteria
The detection system must generate an alert with severity >= 10 and rule ID 100300
("SupportDesk: path traversal pattern in request -- '../' or encoded variant on /kb/view")
within 2 minutes of launch.
A secondary alert at severity >= 12 (rule ID 100301, "sensitive file read via /kb/view --
supportdesk.db or seed.js") must fire when a known sensitive filename is requested.

### Stop criteria
Stopping conditions:
- Alert rule ID 100300 generated and visible in the Wazuh dashboard (primary success -- stop).
- Contents of a file outside `public/kb` confirmed in the response (impact proven).
- Maximum duration of 5 minutes reached without an alert (failure -- investigate the chain).
- Any out-of-scope impact detected (host unresponsive, write observed, log pipeline down).

### MITRE ATT&CK mapping
Targeted technique: T1083 -- File and Directory Discovery.
Exploitation: T1190 -- Exploit Public-Facing Application.
Impact: T1005 -- Data from Local System (reading source, database, and OS files).
