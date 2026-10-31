#!/bin/bash
# Teste les règles custom SupportDesk via wazuh-logtest (simulation, sans attaque réelle).
# Chaque cas injecte une ou plusieurs lignes de log JSON dans le manager et vérifie
# que la règle attendue se déclenche. Prérequis : la stack tourne (docker compose up -d)
# et wazuh.manager a chargé config/wazuh_rules/local_rules.xml.

set -u
SERVICE="wazuh.manager"
LOGTEST="/var/ossec/bin/wazuh-logtest"
PASS=0; FAIL=0

# feed <nb_lignes> <json> : répète la ligne N fois et la passe à wazuh-logtest
feed() {
  local n="$1" line="$2"
  # NB: wazuh-logtest écrit son rapport sur STDERR -> on redirige 2>&1
  yes "$line" | head -n "$n" | docker compose exec -T "$SERVICE" "$LOGTEST" 2>&1
}

# check <nom> <rule_id_attendu> <nb_lignes> <json>
check() {
  local name="$1" expected="$2" n="$3" json="$4"
  local out seen
  out="$(feed "$n" "$json")"
  # Une règle de corrélation (ex. brute force) se déclenche une seule fois au
  # franchissement du seuil, pas forcément sur la derniere ligne -> on vérifie
  # que l'id attendu apparaît quelque part dans la séquence.
  if printf '%s\n' "$out" | grep -qE "id: '$expected'"; then
    echo "  OK   $name -> rule $expected"
    PASS=$((PASS+1))
  else
    seen="$(printf '%s\n' "$out" | grep -oE "id: '[0-9]+'" | sort -u | tr '\n' ' ')"
    echo "  FAIL $name -> attendu $expected, vu: ${seen:-aucune}"
    FAIL=$((FAIL+1))
  fi
}

echo "== Test des règles Wazuh SupportDesk =="

# 1. Auth failure isolé -> 100001 (level 5)
check "auth_failure (1 ligne)" 100001 1 \
  '{"timestamp":"2026-10-30T10:00:00.000Z","event_type":"auth_failure","source_ip":"203.0.113.42","user":"admin","endpoint":"/login","method":"POST","status_code":302,"message":"x"}'

# 2. Brute force : 9 echecs meme IP en <60s -> escalade 100002 (level 10)
check "brute_force (9 lignes)" 100002 9 \
  '{"timestamp":"2026-10-30T10:00:00.000Z","event_type":"auth_failure","source_ip":"203.0.113.42","user":"admin","endpoint":"/login","method":"POST","status_code":302,"message":"x"}'

# 3. SQL injection sur ticket_search (body en STRING, cf. Point 1) -> 100010 (level 12)
check "sql_injection (body string)" 100010 1 \
  '{"timestamp":"2026-10-30T10:00:00.000Z","event_type":"ticket_search","source_ip":"203.0.113.42","user":"jdupont","endpoint":"/tickets/search","method":"POST","status_code":200,"body":"{\"q\":\"'"'"' OR 1=1--\"}"}'

echo "== Resultat : $PASS OK / $FAIL FAIL =="
[ "$FAIL" -eq 0 ]
