#!/bin/bash
# Teste les règles custom SupportDesk via wazuh-logtest (simulation, sans attaque réelle).
# Chaque cas injecte une ou plusieurs lignes de log JSON dans le manager et vérifie
# que la règle attendue se déclenche. Prérequis : la stack tourne (docker compose up -d)
# et wazuh.manager a chargé config/wazuh_rules/local_rules.xml.
# NB: les payloads incluent 'timestamp' (comme les vrais logs) car nos règles sont
# branchées sous la règle native 86600 qui exige ce champ.

set -u
SERVICE="wazuh.manager"
LOGTEST="/var/ossec/bin/wazuh-logtest"
TS='"timestamp":"2026-10-30T10:00:00.000Z"'
PASS=0; FAIL=0

feed() {  # feed <nb_lignes> <json>
  local n="$1" line="$2"
  # NB: wazuh-logtest écrit son rapport sur STDERR -> 2>&1
  yes "$line" | head -n "$n" | docker compose exec -T "$SERVICE" "$LOGTEST" 2>&1
}

check() {  # check <nom> <rule_id_attendu> <nb_lignes> <json>
  local name="$1" expected="$2" n="$3" json="$4" out seen
  out="$(feed "$n" "$json")"
  if printf '%s\n' "$out" | grep -qE "id: '$expected'"; then
    echo "  OK   $name -> rule $expected"; PASS=$((PASS+1))
  else
    seen="$(printf '%s\n' "$out" | grep -oE "id: '[0-9]+'" | sort -u | tr '\n' ' ')"
    echo "  FAIL $name -> attendu $expected, vu: ${seen:-aucune}"; FAIL=$((FAIL+1))
  fi
}

echo "== Test des règles Wazuh SupportDesk =="

# 100000 : auth_failure isolé
check "auth_failure (base 100000)" 100000 1 \
  "{$TS,\"event_type\":\"auth_failure\",\"source_ip\":\"203.0.113.42\",\"user\":\"admin\",\"endpoint\":\"/login\",\"method\":\"POST\",\"status_code\":302,\"message\":\"x\"}"

# 100100 : brute force (9 échecs même IP)
check "brute force (100100)" 100100 9 \
  "{$TS,\"event_type\":\"auth_failure\",\"source_ip\":\"203.0.113.42\",\"user\":\"admin\",\"endpoint\":\"/login\",\"method\":\"POST\",\"status_code\":302,\"message\":\"x\"}"

# 100200 : SQL injection (body string)
check "sql injection (100200)" 100200 1 \
  "{$TS,\"event_type\":\"ticket_search\",\"source_ip\":\"203.0.113.42\",\"user\":\"jdupont\",\"endpoint\":\"/tickets/search\",\"method\":\"POST\",\"status_code\":200,\"body\":\"{\\\"search\\\":\\\"' OR 1=1--\\\"}\"}"

# 100300 : path traversal (query string, sans fichier sensible)
check "path traversal (100300)" 100300 1 \
  "{$TS,\"event_type\":\"not_found\",\"source_ip\":\"203.0.113.42\",\"user\":\"jdupont\",\"endpoint\":\"/kb/view\",\"method\":\"GET\",\"status_code\":404,\"query\":\"doc=../../foo\"}"

# 100301 : lecture fichier sensible via traversal (enfant de 100300)
check "sensitive file via traversal (100301)" 100301 1 \
  "{$TS,\"event_type\":\"not_found\",\"source_ip\":\"203.0.113.42\",\"user\":\"jdupont\",\"endpoint\":\"/kb/view\",\"method\":\"GET\",\"status_code\":404,\"query\":\"doc=../../etc/passwd\"}"

echo "== Resultat : $PASS OK / $FAIL FAIL =="
[ "$FAIL" -eq 0 ]
