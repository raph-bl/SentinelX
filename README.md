<h1 align="center">SentinelX</h1>

<p align="center">
  <strong>An intentionally vulnerable web app, instrumented end to end,<br>
  and the detection pipeline that watches it.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-20-339933?logo=node.js&logoColor=white" alt="Node.js 20">
  <img src="https://img.shields.io/badge/Express-4.18-000000?logo=express&logoColor=white" alt="Express 4">
  <img src="https://img.shields.io/badge/Wazuh-4.9.0-005C8A?logo=wazuh&logoColor=white" alt="Wazuh 4.9.0">
  <img src="https://img.shields.io/badge/Prometheus-latest-E6522C?logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/Grafana-latest-F46800?logo=grafana&logoColor=white" alt="Grafana">
  <img src="https://img.shields.io/badge/Docker%20Compose-ready-2496ED?logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/tests-8%20passing-success" alt="8 tests passing">
  <img src="https://img.shields.io/badge/coverage-78%25%20lines-yellow" alt="78% line coverage">
</p>

---

> [!WARNING]
> **SupportDesk is vulnerable by design** (SQL injection, path traversal, SSRF, plaintext passwords in the
> database). This repository is a **teaching lab**. Never deploy it on an internet-facing machine, and only
> run the attack scenarios against your own local instance.

## Table of contents

- [The project in two minutes](#the-project-in-two-minutes)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Access and demo accounts](#access-and-demo-accounts)
- [Observability](#observability)
- [Detection](#detection)
- [Attack scenarios](#attack-scenarios)
- [Tests](#tests)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Measured results](#measured-results)
- [Known limitations](#known-limitations)

## The project in two minutes

**SupportDesk** is an internal helpdesk ticket manager (Node.js / Express / EJS / SQLite) that ships with
realistic flaws. Around it, **Sentinel X** builds the full pipeline of a miniature SOC:

1. **Instrument** — every request emits a flat JSON log line drawn from a closed schema (14 `event_type`
   values), and the app exposes Prometheus metrics on `/metrics`.
2. **Detect** — Wazuh reads those logs and applies 8 custom rules mapped to MITRE ATT&CK, three of which
   are correlation rules (brute force, 5xx burst, sensitive file read).
3. **Measure** — a legitimate traffic generator makes it possible to compute a **false positive rate**, and
   every attack scenario is replayable through an *attack plan* and its *runbook*.

The technical contract between the instrumentation track and the detection track is frozen in
**[`CONTRACT.md`](CONTRACT.md)**: log format, closed event list, metrics, ports, volumes.

## Architecture

```mermaid
flowchart LR
    subgraph app-net
        A["🎫 SupportDesk<br/><code>:3000</code>"]
        P["📊 Prometheus<br/><code>:9090</code>"]
        G["📈 Grafana<br/><code>:3001</code>"]
    end

    subgraph wazuh-net
        WM["🔎 Wazuh manager<br/>rules + analysisd"]
        WI["🗄️ Wazuh indexer<br/><code>:9200</code>"]
        WD["🖥️ Wazuh dashboard<br/><code>:443</code>"]
    end

    V[("volume<br/>app-logs")]

    A -- "app.log (JSON)" --> V
    V -- "logcollector" --> WM
    WM --> WI --> WD
    A -- "/metrics (15s)" --> P --> G
```

| Pipeline | Path |
|---|---|
| **Detection** | `middleware/logger.js` → `/var/log/supportdesk/app.log` → `app-logs` volume → Wazuh logcollector → JSON decoder (built-in rule `86600`) → `local_rules.xml` → `alerts.json` → dashboard |
| **Performance** | `middleware/metrics.js` → `GET /metrics` → Prometheus scrape (15 s) → provisioned Grafana dashboard |

## Quick start

### Requirements

| | |
|---|---|
| Docker + Docker Compose | v2 (`docker compose`, no hyphen) |
| Available RAM | **8 to 12 GB** — the Wazuh indexer (OpenSearch) alone wants ~4 GB of heap |
| Free host ports | `3000`, `3001`, `9090`, `9200`, `443`, `1514`, `1515`, `5140/udp`, `55000` |

### Launch

```bash
git clone https://github.com/raph-bl/SentinelX.git
cd SentinelX

cp .env.example .env     # then replace every "change-me"
docker compose up -d --build
```

> [!NOTE]
> Wazuh takes **5 to 15 minutes** to become fully operational on first start.
> Follow it with `docker compose logs -f wazuh.manager`.

To run the application alone, without the monitoring stack:

```bash
docker compose up -d --build supportdesk
```

## Access and demo accounts

| Service | URL | Credentials |
|---|---|---|
| SupportDesk | <http://localhost:3000> | see below |
| Grafana | <http://localhost:3001> | `GRAFANA_USER` / `GRAFANA_PASSWORD` from `.env` |
| Prometheus | <http://localhost:9090> | — |
| Wazuh dashboard | <https://localhost> | `INDEXER_USERNAME` / `INDEXER_PASSWORD` from `.env` |

Accounts created by `database/seed.js` (passwords are **stored in plaintext**, which is deliberate):

| Role | Email | Password |
|---|---|---|
| admin | `admin@supportdesk.local` | `Admin_123` |
| admin | `helpdesk@supportdesk.local` | `Help_123` |
| user | `jdupont@supportdesk.local` *(and 7 more accounts)* | `User_123` |

## Observability

### Structured logs

One flat JSON line per request, UTF-8, no nested objects — directly digestible by the Wazuh JSON decoder.
The full schema lives in [`CONTRACT.md` §3](CONTRACT.md).

```json
{"timestamp":"2026-10-20T14:32:11.423Z","level":"WARN","event_type":"auth_failure","source_ip":"203.0.113.42","user":"admin@example.com","endpoint":"/login","method":"POST","status_code":302,"message":"Login failed","body":"{\"email\":\"admin@example.com\",\"password\":\"***\"}","user_agent":"curl/8.5.0"}
```

Capture rules worth knowing:

- **A closed list of 14 `event_type` values** (`auth_failure`, `auth_success`, `access_denied`, `ticket_search`, `kb_view`, `server_error`…), one per line, first matching rule wins.
- **Passwords are masked** (`***`); `query` and `body`, on the other hand, are logged **raw**, with no decoding or sanitizing, so that the rules can see attack patterns.
- `GET /metrics` is neither logged nor counted, to keep scrape noise out of the measurements.

### Metrics

`GET /metrics` exposes, via `prom-client`:

| Metric | Type | Labels |
|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status_code` |
| `http_request_duration_seconds` | histogram | `method`, `route` |
| `app_events_total` | counter | `event_type` |
| `process_*`, `nodejs_*` | — | Node defaults |

The `route` label is always the route **pattern** (`/tickets/:id`, or `unmatched`), never the actual path:
no cardinality explosion, and never an IP, a user or a payload in a label.

The Grafana dashboard (HTTP requests, authentication attempts, request durations) is provisioned
automatically from `config/grafana/`.

## Detection

8 custom rules in [`config/wazuh_rules/local_rules.xml`](config/wazuh_rules/local_rules.xml), all chained
under the built-in rule `86600` and mapped to MITRE ATT&CK.

| ID | Level | Trigger | MITRE |
|---|:---:|---|---|
| `100000` | 5 | `event_type = auth_failure` *(building block)* | T1110 |
| `100001` | 3 | `event_type = server_error` *(building block)* | — |
| `100100` | **10** | 8 `auth_failure` within 60 s from the same `source_ip` | T1110 |
| `100101` | **12** | `auth_success` within 120 s of a `100100` | T1110 |
| `100200` | **12** | SQL injection pattern in a `ticket_search` body | T1190 |
| `100201` | **7** | 6 `server_error` within 60 s from the same `source_ip` | T1190 |
| `100300` | **12** | `../`, `..%2f` or `%2e%2e` in the query string | T1083 |
| `100301` | **12** | sensitive file (`/etc/passwd`, `supportdesk.db`, `seed.js`) via `100300` | T1005 |

> Rules `100000` and `100001` fire **by design** on every typo and every 500. The quality indicator the team
> settled on therefore counts only alerts at **level ≥ 7**.

### Exercising the rules

```bash
./scripts/wazuh/run_wazuh_tests.sh       # wazuh-logtest simulation, no real attack
./scripts/wazuh/run_wazuh_simulation.sh  # real attack traffic -> real alerts
./check_alerts.sh                        # tail alerts.log live
```

## Attack scenarios

Each scenario comes as two documents: an **attack plan** (rules of engagement, success criteria, written
beforehand) and a **runbook** (reproducible trace, written after execution).

| # | Scenario | Underlying flaw | Detection | Status |
|---|---|---|---|---|
| 01 | [Brute force on `/login`](attack_plans/01-auth-bruteforce.md) | no rate limiting on authentication | `100100` / `100101` | ✅ `100100` confirmed live |
| 02 | [SQL injection on `/tickets/search`](attack_plans/02-sql-injection.md) | direct concatenation into the `LIKE` clause (`routes/tickets.js`) | `100200` / `100201` | ✅ `100200` confirmed live |
| 03 | [Path traversal on `/kb/view`](attack_plans/03-path-traversal.md) | `path.join` on an unvalidated parameter (`routes/kb.js`) | `100300` / `100301` | ✅ `100301` confirmed live |

Matching runbooks: [`runbooks/01`](runbooks/01-auth-bruteforce.md) ·
[`runbooks/02`](runbooks/02-sql-injection.md) · [`runbooks/03`](runbooks/03-path-traversal.md)

### Measuring false positives

`scripts/traffic/traffic.py` simulates legitimate users (login → dashboard → tickets → searches, comments,
knowledge base → logout), with one IP per user, a deterministic seed and a configurable rate of password
typos.

```bash
python3 scripts/traffic/traffic.py --duration 600 --users 5 --seed 42 --output run.csv
```

## Tests

A functional suite of 8 cases (`node:test` + `supertest`) covering the critical endpoints, **including the
content of the emitted logs**: tests 7 and 8 assert that a successful and a failed `POST /login` — two
`302` responses that only the `Location` header tells apart — are classified as `auth_success` and
`auth_failure` respectively.

```bash
./scripts/wazuh/run_tests.sh                            # with coverage
docker compose run --build --rm supportdesk npm test    # tests only
```

> [!IMPORTANT]
> Tests run **inside the container**: `better-sqlite3` is a native module compiled for `node:20-alpine`,
> not for the host's Node. The `--build` flag is required, since `docker compose run` does not rebuild the
> image and would otherwise ignore your changes.

Last run: **8 tests, 0 failures** — 78.16 % of lines, 72.45 % of branches, 64.44 % of functions.
Coverage is deliberately concentrated on the security and observability components (`logger`, `metrics`,
`auth`: 84 to 100 % of lines). Breakdown in [`docs/tests.md`](docs/tests.md).

## Repository layout

```
.
├── app.js                      # Express entry point
├── routes/                     # auth · tickets · kb · admin · profile
├── middleware/
│   ├── logger.js               # JSON logging + event_type classification
│   ├── metrics.js              # Prometheus counters and histograms
│   └── auth.js                 # session guard and role check
├── database/                   # SQLite schema and seed
├── views/ · public/            # EJS views and Bootstrap assets
├── config/
│   ├── wazuh_rules/            # 👈 the 8 detection rules
│   ├── wazuh_cluster/          # ossec.conf (app.log collection)
│   ├── prometheus/ · grafana/  # scrape config and provisioned dashboards
│   └── credentials/            # default passwords for the Wazuh stack
├── scripts/
│   ├── wazuh/                  # rule tests, attack simulation, unit tests
│   └── traffic/                # legitimate traffic generator (FP measurement)
├── attack_plans/               # attack plans (before execution)
├── runbooks/                   # reproducible traces (after execution)
├── docs/                       # alert qualification, tests
├── tests/                      # functional suite
├── CONTRACT.md                 # 👈 instrumentation ↔ detection technical contract
├── docker-compose.yml          # app + Prometheus + Grafana (includes wazuh/)
└── wazuh/docker-compose.yml    # manager + indexer + dashboard
```

## Documentation

| Document | Contents |
|---|---|
| [`CONTRACT.md`](CONTRACT.md) | Technical contract: log schema, `event_type` list, metrics, ports, volumes, environment variables |
| [`docs/alert.md`](docs/alert.md) | Alert qualification report: protocol, false positive rate, true and false negatives |
| [`docs/tests.md`](docs/tests.md) | Test strategy and detailed coverage figures |
| `attack_plans/` · `runbooks/` | One plan and one runbook per attack scenario |

## Measured results

Reference run: **759 requests** of normal traffic (600 s, 5 concurrent users, seed 42).

| Indicator | Value |
|---|---|
| False positive rate, detection alerts (level ≥ 7) | **0.00 %** |
| False positive rate, all alerts | 0.53 % (4 `100000` alerts = the 4 simulated password typos) |
| True positives confirmed live | 3 scenarios out of 3 |

## Known limitations

They are owned and documented rather than hidden — details in [`docs/alert.md`](docs/alert.md) §9.

- **Rule `100200` is too broad.** Its pattern accepts a bare `'`, `--` or `order by`, so legitimate searches
  (`wi-fi -- guest`, `order by date`) raise a level 12 alert. Confirmed false positive.
- **One false negative is proven.** An injection that crashes the query (`x' union select 1,2,3--`) returns a
  500: `classify()` logs it as `server_error` before reaching the `ticket_search` branch, so `100200` never
  sees it. The real fix is to parameterize the SQL query in `routes/tickets.js`.
- **`source_ip` is spoofable.** The `X-Forwarded-For` header is trusted (`trust proxy`), which allows IP
  rotation to slip past the correlation rules.
- **The 0 % false positive rate is not representative**: synthetic traffic, 6 search terms with no special
  characters, a 10-minute window, a single seed.
- **No rule has been fixed yet**, so there is no before/after measurement.