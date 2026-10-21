## Attack Plan -- SQL Injection on filtered tickets
### Rules of engagement
Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Additional constraints specific to this scenario:
- Read-only exploitation: SELECT-based extraction only, no `DROP`/`DELETE`/`UPDATE`
  (the seeded database must stay intact for later scenarios).
- Run from a single, fixed source IP sent via the `X-Forwarded-For` header so `source_ip`
  is deterministic and not the Docker bridge address.
- A valid authenticated session is required (both routes sit behind `isAuthenticated`);
  use the seeded `jdupont@supportdesk.local` account, not an admin one.
- Stop the realistic traffic script before launch so the injection burst is isolated.

### Scope
Endpoints within the attack perimeter:
- `GET /tickets` -- injectable query parameters: `status`, `priority`, `sort`, `dir`
(concatenated into the WHERE clause and the ORDER BY clause)
- `POST /tickets/search` -- injectable body parameter: `search`
(concatenated into a LIKE clause -- primary UNION vector)


### Attack vectors
- UNION-based SQL injection via `POST /tickets/search` (`search` param) to exfiltrate the
  `users` table (emails + plaintext passwords + roles) into the rendered tickets list.
  The SELECT returns 11 columns, so the UNION must supply 11 columns, e.g.:
  `%' UNION SELECT id, email, password, role, NULL, NULL, NULL, NULL, NULL, username, NULL FROM users --`
- Boolean-based blind injection via `GET /tickets` (`status` / `priority`), e.g.
  `status=resolved' AND '1'='1` vs `status=resolved' AND '1'='2`.
- ORDER BY injection via `GET /tickets` (`sort` / `dir`), unquoted concatenation into the
  `ORDER BY` clause.

Note: `better-sqlite3` allows a single statement per query, so stacked queries
(`; DROP TABLE ...`) are not possible. Malformed payloads surface as HTTP 500 via the
global error handler -- a secondary detection signal.

### Tools used
- `sqlmap` (primary -- automated detection + UNION/boolean exploitation; `--cookie` for the session)
- `curl` (manual confirmation of the boolean and ORDER BY payloads)
- Browser (manual UNION payload through the search bar to view exfiltrated rows)

### Success criteria
The detection system must generate an alert with severity >= 10 and rule ID 100200
("SupportDesk: SQL injection pattern in query/body") within 2 minutes of launch.
A secondary alert at severity >= 7 (rule ID 100201, "spike of HTTP 500 from same source_ip")
must fire when sqlmap sends malformed payloads.

### Stop criteria
Stopping conditions:
- Alert rule ID 100200 generated and visible in the Wazuh dashboard (primary success -- stop).
- `users` table contents (emails/passwords) extracted and confirmed in the response.
- Maximum duration of 5 minutes reached without an alert (failure -- investigate the chain).
- Any out-of-scope impact detected (host unresponsive, write operation observed, log pipeline down).

### MITRE ATT&CK mapping
Targeted technique: T1190 -- Exploit Public-Facing Application.
Impact: T1213 -- Data from Information Repositories (exfiltration of the credentials table).
