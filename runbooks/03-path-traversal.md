# Runbook -- Path traversal on /kb/view

Trace reproductible du scénario [`attack_plans/03-path-traversal.md`](../attack_plans/03-path-traversal.md).

| | |
|---|---|
| **Scénario** | Traversée de chemin sur le lecteur KB (`GET /kb/view?doc=...`) |
| **Cible** | `http://localhost:3000` (authentifié) |
| **Chaîne** | app -> `app.log` -> Wazuh -> `alerts.log` |
| **Règles** | **100300** (motif `../` dans query, level 12), 100301 (fichier sensible, level 12) |
| **Résultat** | ✅ opérationnel en live (débloqué par le Point 1 : `query` en string) |

## 1. Prérequis
Stack up, règles chargées. Route protégée -> session authentifiée.

## 2. Commandes
```bash
./run_wazuh_simulation.sh          # inclut l'étape traversal
```
Équivalent manuel :
```bash
IP="203.0.113.150"; JAR=$(mktemp)
curl -s -o /dev/null -c "$JAR" -H "X-Forwarded-For: $IP" \
  --data "email=admin@supportdesk.local&password=Admin_123" http://localhost:3000/login
curl -s -o /dev/null -b "$JAR" -H "X-Forwarded-For: $IP" \
  --get --data-urlencode "doc=../../etc/passwd" http://localhost:3000/kb/view
rm -f "$JAR"
```

## 3. Observations
`app.log` -- `query` est désormais une **string** (Point 1), un 404 est classé `not_found` :
```json
{"timestamp":"...","event_type":"not_found","source_ip":"203.0.113.150","user":"admin",
 "endpoint":"/kb/view","method":"GET","status_code":404,"response_time_ms":2,
 "query":"doc=..%2F..%2Fetc%2Fpasswd","user_agent":"curl/8.x"}
```
Validation logique : `./run_wazuh_tests.sh` -> `path traversal (100300) OK` + `sensitive file (100301) OK`.

## 4. Alertes (live)
```
rule 100301 (sensitive file read) : 2
Rule: 100301 (level 12) -> 'SupportDesk: sensitive file requested via traversal (/kb/view)'
```
> 100301 est l'enfant de 100300 : quand il se déclenche, Wazuh rapporte la règle la plus
> spécifique (100301), ce qui prouve que 100300 a aussi matché. Un payload traversal sans
> fichier sensible (`doc=../../foo`) déclenche 100300 seul.

## 5. Critères (plan) et verdict
| Critère | Attendu | Observé | Verdict |
|---|---|---|---|
| Alerte traversal sévérité >= 10, rule 100300 | level 10+ | `100300`/`100301` level 12, en live | ✅ |
| Alerte « lecture fichier sensible », rule 100301 | level 12 | `100301` level 12, en live | ✅ |

## 6. Reproduction
`./run_wazuh_simulation.sh` -> `./check_alerts.sh`.

## 7. Limites
- La traversal sur `../../etc/passwd` renvoie 404 ici (fichier hors du dossier KB non trouvé) ;
  l'alerte repose sur le **motif dans la query**, pas sur une lecture réussie.
- Motif pcre2 à surveiller pour les faux positifs (un doc légitime contenant `..` ).
