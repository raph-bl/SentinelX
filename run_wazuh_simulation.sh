#!/bin/bash
# run_wazuh_simulation.sh
# Génère du VRAI trafic contre SupportDesk pour alimenter la chaîne de détection
# complète : app -> app.log -> Wazuh (logcollector + analysisd) -> alerts.log.
# Contrairement à run_wazuh_tests.sh (wazuh-logtest, simulation), ce script
# produit de vraies alertes visibles dans check_alerts.sh et le dashboard.
#
# Prérequis : la stack tourne (docker compose up -d) et l'app répond sur $TARGET.
# Usage : ./run_wazuh_simulation.sh [cible]   (défaut http://localhost:3000)

set -u
TARGET="${1:-http://localhost:3000}"
# IP attaquante aléatoire à chaque run : source_ip déterministe pour CE run, et on
# évite la fenêtre d'« ignore » de Wazuh qui supprime une alerte de corrélation
# déjà déclenchée récemment pour la même IP.
ATTACKER_IP="203.0.113.$(( RANDOM % 240 + 10 ))"
BRUTE_N=12                           # nb de logins ratés (seuil brute force = 8/60s)
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

ADMIN_EMAIL="admin@supportdesk.local"
ADMIN_PASS="Admin_123"

xff=(-H "X-Forwarded-For: $ATTACKER_IP")

count_alerts() {  # count_alerts <rule_id> -> nb d'alertes pour cette règle et l'IP attaquante
  local n
  n="$(docker compose exec -T wazuh.manager sh -c \
    "grep '$ATTACKER_IP' /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c '\"id\":\"$1\"'" 2>/dev/null)"
  echo "${n:-0}" | tr -d '[:space:]'
}

echo "== Simulation de trafic -> $TARGET (attaquant $ATTACKER_IP) =="

# --- Scénario 1 : brute force authentification -----------------------------
echo "[1] Brute force : $BRUTE_N logins ratés sur /login"
for i in $(seq 1 "$BRUTE_N"); do
  curl -s -o /dev/null "${xff[@]}" \
    --data "email=$ADMIN_EMAIL&password=wrong$i" "$TARGET/login"
done

# --- Session authentifiée (pour les scénarios derrière isAuthenticated) ----
echo "[*] Ouverture d'une session authentifiée (admin)"
curl -s -o /dev/null -c "$JAR" "${xff[@]}" \
  --data "email=$ADMIN_EMAIL&password=$ADMIN_PASS" "$TARGET/login"

# --- Scénario 2 : injection SQL sur la recherche de tickets ----------------
echo "[2] SQL injection : POST /tickets/search"
for payload in "' OR 1=1--" "' UNION SELECT username,password FROM users--"; do
  curl -s -o /dev/null -b "$JAR" "${xff[@]}" \
    --data-urlencode "search=$payload" "$TARGET/tickets/search"
done

# --- Scénario 3 : path traversal sur le lecteur KB -------------------------
echo "[3] Path traversal : GET /kb/view?doc=../../..."
for doc in "../../etc/passwd" "../../../supportdesk.db"; do
  curl -s -o /dev/null -b "$JAR" "${xff[@]}" \
    --get --data-urlencode "doc=$doc" "$TARGET/kb/view"
done

# --- Un peu de trafic normal (baseline) ------------------------------------
echo "[*] Trafic normal (dashboard, liste tickets)"
curl -s -o /dev/null -b "$JAR" "${xff[@]}" "$TARGET/dashboard"
curl -s -o /dev/null -b "$JAR" "${xff[@]}" "$TARGET/tickets"

# --- Laisse Wazuh ingérer puis rend compte ---------------------------------
echo "[*] Attente de l'ingestion par Wazuh (8s)..."
sleep 8

echo "== Alertes générées (IP $ATTACKER_IP) =="
printf "  rule 100001 (auth_failure) : %s\n"  "$(count_alerts 100001)"
printf "  rule 100002 (brute force)  : %s\n"  "$(count_alerts 100002)"
printf "  rule 100010 (sql injection): %s\n"  "$(count_alerts 100010)"
echo
echo "Détail : ./check_alerts.sh   (ou dashboard https://localhost:443)"
echo "Note : 100010 (SQLi) et la future règle traversal ne se déclenchent qu'une"
echo "       fois le Point 1 fait (query/body en strings plates dans les logs)."
