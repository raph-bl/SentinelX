# Runbook -- SQL Injection on /tickets/search

Trace reproductible du scénario [`attack_plans/02-sql-injection.md`](../attack_plans/02-sql-injection.md).

| | |
|---|---|
| **Scénario** | Injection SQL via la recherche de tickets (`POST /tickets/search`) |
| **Cible** | `http://localhost:3000` (authentifié) |
| **Chaîne** | app -> `app.log` -> Wazuh -> `alerts.log` |
| **Règles** | **100200** (motif SQLi dans body, level 12), 100201 (rafale de 500, level 7) |
| **Résultat** | ✅ opérationnel en live (débloqué par le Point 1 : `body` en string) |

## 1. Prérequis
Stack up, règles chargées. Recherche protégée -> session authentifiée (compte seedé).

## 2. Commandes
```bash
./run_wazuh_simulation.sh          # inclut l'étape SQLi
```
Équivalent manuel :
```bash
IP="203.0.113.150"; JAR=$(mktemp)
curl -s -o /dev/null -c "$JAR" -H "X-Forwarded-For: $IP" \
  --data "email=admin@supportdesk.local&password=Admin_123" http://localhost:3000/login
curl -s -o /dev/null -b "$JAR" -H "X-Forwarded-For: $IP" \
  --data-urlencode "search=' OR 1=1--" http://localhost:3000/tickets/search
rm -f "$JAR"
```

## 3. Observations
`app.log` -- `body` est désormais une **string** (Point 1), le payload est visible :
```json
{"timestamp":"...","event_type":"ticket_search","source_ip":"203.0.113.150","user":"admin",
 "endpoint":"/tickets/search","method":"POST","status_code":200,"response_time_ms":6,
 "body":"{\"search\":\"' OR 1=1--\"}","user_agent":"curl/8.x"}
```
Validation logique : `./run_wazuh_tests.sh` -> `sql injection (100200) OK`.

## 4. Alertes (live)
```
rule 100200 (sql injection) : 1
Rule: 100200 (level 12) -> 'SupportDesk: SQL injection pattern in search body (user admin)'
```

## 5. Critères (plan) et verdict
| Critère | Attendu | Observé | Verdict |
|---|---|---|---|
| Alerte SQLi sévérité >= 10, rule 100200 | level 10+ | `100200` level 12, en live | ✅ |
| Alerte secondaire « rafale de 500 », rule 100201 | level 7 | règle chargée, non testée en live (besoin de 500) | 🟡 |

## 6. Reproduction
`./run_wazuh_simulation.sh` -> `./check_alerts.sh`. Résultat attendu : ligne `ticket_search`
dans `app.log` + alerte `100200`.

## 7. Limites
- Motifs pcre2 larges (`--`, `'`, `order by`) -> risque de faux positifs, à mesurer avec le
  script de trafic réaliste.
- `100201` (rafale de 500) dépend de la base `100001` (event_type server_error) ; non vérifiée
  en live faute de moyen simple de générer des 500.
