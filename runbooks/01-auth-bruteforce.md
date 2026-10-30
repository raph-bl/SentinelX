# Runbook -- Authentication brute force on /login

Trace reproductible du scénario [`attack_plans/01-auth-bruteforce.md`](../attack_plans/01-auth-bruteforce.md).

| | |
|---|---|
| **Scénario** | Brute force authentification (`POST /login`) |
| **Cible** | `http://localhost:3000` |
| **Chaîne** | app -> `app.log` -> Wazuh -> `alerts.log` |
| **Règles** | 100000 (base auth_failure), **100100** (brute force, level 10), 100101 (login réussi après brute force, level 12) |
| **Résultat** | ✅ opérationnel (100100 en live ; 100101 validé en logtest) |

## 1. Prérequis
Stack up, règles chargées sans `CRITICAL` (`grep -i CRITICAL /var/ossec/logs/ossec.log`).

## 2. Commandes
```bash
./run_wazuh_simulation.sh          # inclut le brute force (15 logins ratés, IP aléatoire)
```
Équivalent manuel :
```bash
IP="203.0.113.42"
for i in $(seq 1 15); do
  curl -s -o /dev/null -H "X-Forwarded-For: $IP" \
    --data "email=admin@supportdesk.local&password=wrong$i" http://localhost:3000/login
done
```
> Utiliser une IP non vue récemment (fenêtre d'« ignore » de Wazuh sur les corrélations).

## 3. Observations
`app.log` : une ligne `auth_failure` par échec (`body` string, mot de passe masqué) :
```json
{"timestamp":"...","level":"WARN","event_type":"auth_failure","source_ip":"203.0.113.42",
 "endpoint":"/login","method":"POST","status_code":302,"response_time_ms":3,
 "body":"{\"email\":\"admin@supportdesk.local\",\"password\":\"***\"}","user_agent":"curl/8.x"}
```
Validation logique (déterministe) : `./run_wazuh_tests.sh` -> `brute force (100100) OK`.

## 4. Alertes (live, `./check_alerts.sh` / `alerts.json`)
```
rule 100000 (auth_failure)  : 14
rule 100100 (brute force)   : 1
Rule: 100100 (level 10) -> 'SupportDesk: brute force -- 8+ auth_failure from same source_ip within 60s (...)'
```

## 5. Critères (plan) et verdict
| Critère | Attendu | Observé | Verdict |
|---|---|---|---|
| Alerte brute force, sévérité >= 10, rule 100100 | level 10 | `100100` level 10 | ✅ |
| Alerte login réussi après brute force, sévérité >= 12, rule 100101 | level 12 | logtest ✅ ; live sensible au timing | 🟡 |

## 6. Reproduction
`docker compose up -d` -> `./run_wazuh_simulation.sh` -> `./check_alerts.sh`.
Si 0 alerte alors que `app.log` se remplit : `docker compose restart wazuh.manager`.

## 7. Limites
- **100100 sensible au timing** en live (seuil 8/60s + latence d'ingestion) : 15 ratés = fiable.
- **100101** fiable en logtest, capricieux en live (corrélation auth_success après 100100).
- `source_ip` falsifiable via `X-Forwarded-For` (CONTRACT §4.3).
- Le logcollector Wazuh peut décrocher -> restart du manager (healthcheck à prévoir).
