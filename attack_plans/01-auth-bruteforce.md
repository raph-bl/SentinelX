## Attack Plan -- Authentication brute force on /login

### Rules of engagement
Attacks are limited to the local dockerized instance (`http://localhost:3000`).
No third-party targets, no network scanning outside scope.
Additional constraints specific to this scenario:
- Target only the seeded accounts (`admin@supportdesk.local`, `helpdesk@supportdesk.local`,
  `jdupont@supportdesk.local`) using a bounded wordlist (<= 500 candidates per account).
- Rate capped at 20 requests/second to keep the host responsive and the log volume readable.
- Run the whole scenario from a single, fixed source IP sent via the `X-Forwarded-For` header so
  the generated `source_ip` field is deterministic and not the Docker bridge address.
- The realistic traffic script must be stopped before launch so the brute-force burst is isolated.

### Scope
Endpoints within the attack perimeter:
- `POST /login` (credential submission / primary target)
- `GET /login` (form retrieval only, to observe the `?error=1` redirect on failure)

No other endpoint is in scope for this scenario.

### Attack vectors
- Authentication brute force (horizontal: one account, many passwords).
- Credential stuffing variant (known weak passwords across the seeded accounts).

Note: a failed login returns HTTP 302 to `/login?error=1`, not 401. Detection relies on the
application emitting an explicit `auth_failure` event (per CONTRACT.md), not on the HTTP status.

### Tools used
- `hydra` (primary -- `hydra -L users.txt -P rockyou-top500.txt ... http-post-form`)
- `curl` (manual single-request verification and the final successful-login probe)
- `ffuf` (optional, to replay the wordlist as an alternative request engine)

### Success criteria
The detection system must generate an alert with severity >= 10 and rule ID 100100
("SupportDesk: brute force -- 8+ auth_failure from same source_ip within 60s")
within 2 minutes of launch.
A follow-up alert at severity >= 12 (rule ID 100101, "successful login after brute force")
must fire if the attack ends in a valid authentication.

### Stop criteria
Stopping conditions:
- Alert rule ID 100100 generated and visible in the Wazuh dashboard (primary success -- stop).
- Maximum duration of 5 minutes reached without an alert (failure -- stop and investigate the chain).
- Valid credentials obtained (session cookie returned on `POST /login`).
- Any out-of-scope impact detected (host unresponsive, another endpoint erroring, log pipeline down).

### MITRE ATT&CK mapping
Targeted technique: T1110.001 -- Brute Force: Password Guessing.
Related: T1110.004 -- Brute Force: Credential Stuffing.
