# Rapport de qualification des alertes — Sentinel X

> **Statut : modèle pré-rempli.** Les sections 1 à 4 et 8 sont rédigées à partir du dépôt
> (règles, scripts, runbooks). Les mesures (sections 5 à 7) sont à remplir **avec les
> chiffres réels du run**, marqués `_à remplir_`. Ne jamais y mettre un chiffre estimé.

| | |
|---|---|
| **Application** | SupportDesk (Node.js / Express) |
| **Détection** | Wazuh 4.9.0, règles `config/wazuh_rules/local_rules.xml` |
| **Auteur(s)** | Tara-Nour Monteiro, Flauréanne Soldat, Raphaël Bertaina-Loichemol |
| **Date de la mesure** | 02/11/2026 |

---

## 1. Objectif

Vérifier que le **trafic normal** ne déclenche pas d'alertes de détection, mesurer le
**taux de faux positifs** sur une durée convenue, et qualifier chaque alerte (vrai ou faux
positif, avec justification).

## 2. Définitions et conventions (à valider par l'équipe)

| Terme | Définition retenue |
|---|---|
| **Trafic normal** | Requêtes de `scripts/traffic/traffic.py` : utilisateurs légitimes (comptes du seed), sans aucun payload d'attaque. Aucune attaque ni test manuel pendant la mesure. |
| **Alerte** | Entrée de `alerts.json` du groupe `supportdesk` dans la fenêtre de mesure (fin de trafic + 30 s d'ingestion). |
| **Faux positif (FP)** | Toute alerte déclenchée pendant un run de trafic 100 % normal. |
| **Vrai positif (VP)** | Alerte déclenchée par une attaque de nos scénarios (section 8). |
| **Alerte de détection** | Alerte de niveau **≥ 7** : règles 100100, 100101, 100200, 100201, 100300, 100301. |
| **Alerte de base** | Niveau < 7 : 100000 (échec de connexion, niveau 5) et 100001 (erreur serveur, niveau 3). Ces règles servent surtout de briques pour les règles de détection. |

**Deux taux sont publiés** pour que le jury puisse comparer :

- **Taux A** = alertes (toutes) ÷ requêtes envoyées × 100
- **Taux B** = alertes de détection (niveau ≥ 7) ÷ requêtes envoyées × 100
- Chacun est aussi exprimé en **alertes par heure**.

Décision de l'équipe sur l'indicateur « officiel » : _à remplir (A ou B)_ — justification : _à remplir_.

## 3. Protocole de mesure

| Paramètre | Valeur |
|---|---|
| Outil | `scripts/traffic/traffic.py` (Python 3, bibliothèque `requests`) |
| Version du script | commit _à remplir_ — **gelé avant la mesure** |
| Comptes simulés | `scripts/traffic/seed_users.json` (8 comptes utilisateur du seed) |
| Utilisateurs simultanés | _à remplir_ (défaut du script : 5) |
| Durée | _à remplir_ (défaut du script : 600 s) |
| Graine aléatoire | _à remplir_ (défaut : 42) — même graine pour tout run comparé |
| IP sources simulées | `198.51.100.10` à `198.51.100.14` (via `X-Forwarded-For`, un utilisateur par IP) |
| Comportement | connexion → dashboard → liste de tickets → 1 à 4 actions (consultation, recherche, commentaire, base de connaissances, profil) → déconnexion ; pauses aléatoires de 1 à 5 s ; **5 % de fautes de mot de passe** par tentative |
| Fenêtre d'analyse | début = 1re requête du CSV ; fin = dernière requête + 30 s |

### Pré-requis avant de lancer (cocher)

- [ ] Script de trafic finalisé, **committé**, et relancé deux fois avec la même graine : volumes comparables
- [ ] Stack démarrée et saine (`docker compose ps`), règles chargées (`wazuh-analysisd -t` sans erreur)
- [ ] Chaîne vérifiée : un `auth_failure` manuel produit bien une alerte (dry-run)
- [ ] Aucune attaque, aucun test manuel ni autre script en parallèle
- [ ] Même seed, mêmes paramètres que ceux notés ci-dessus

### Procédure

**Méthode simple (une commande)** : `scripts/traffic/measure_fp.sh` vérifie les pré-requis, lance le
trafic, attend l'ingestion, exporte les alertes et écrit le résultat dans `measurements/result-*.md`.

```bash
scripts/traffic/measure_fp.sh 600 5 42 7     # durée (s), utilisateurs, graine, niveau minimal d'une alerte de détection
```

**Méthode détaillée (équivalente, étape par étape)**

```bash
# 1. Lancer le trafic (noter la sortie : le "Total" est le nombre de requêtes)
python3 scripts/traffic/traffic.py --duration 600 --users 5 --seed 42 --output /tmp/run1.csv | tee /tmp/run1.txt

# 2. Attendre ~1 minute (ingestion Wazuh), puis exporter les alertes
docker compose exec -T wazuh.manager cat /var/ossec/logs/alerts/alerts.json > /tmp/alerts_run1.json

# 3. Compter et détailler
python3 scripts/traffic/count_alerts.py --alerts /tmp/alerts_run1.json \
    --traffic-csv /tmp/run1.csv --min-level 7 --details
```

`count_alerts.py` lit la fenêtre, le nombre de requêtes et le nombre de fautes de mot de
passe simulées directement dans le CSV du trafic, et imprime les tableaux des sections 5 à 7.

## 4. Analyse a priori des règles (hypothèses à confirmer par la mesure)

| Règle | Niveau | Se déclenche quand | Risque de FP sur trafic normal |
|---|---|---|---|
| 100000 | 5 | chaque `auth_failure` | **Certain par conception** : une faute de mot de passe simulée = une alerte. Nombre attendu = nombre de fautes du CSV. |
| 100001 | 3 | chaque `server_error` (HTTP 5xx) | Faible : le trafic normal ne doit produire aucune erreur 5xx. |
| 100100 | 10 | 8 `auth_failure` en 60 s, même `source_ip` | Très faible : il faudrait 8 fautes consécutives sur une même IP. |
| 100101 | 12 | `auth_success` après 100100 | Nul si 100100 ne se déclenche pas. |
| 100200 | 12 | `ticket_search` dont le `body` contient `union select`, `or 1=1`, `order by`, `--` ou `'` | **Faible sur les termes du script, élevé en usage réel** : voir ci-dessous. |
| 100201 | 7 | 6 `server_error` en 60 s, même IP | Très faible. |
| 100300 | 12 | `query` contenant `../` ou `%2e%2e` | Faible : les noms de documents normaux n'en contiennent pas. |
| 100301 | 12 | enfant de 100300, fichier sensible dans `query` | Nul sans 100300. |

### Point d'attention : la règle 100200 est large

Le motif contient `'` et `--`. Une simulation en Python des regex (indicative, **à confirmer avec
`wazuh-logtest`**) donne, sur le champ `body` d'un `ticket_search` :

| Recherche légitime | Alerte 100200 ? |
|---|---|
| `battery`, `vpn`, `screen`, `mot de passe oublié` | non |
| `l'imprimante`, `d'accès badge` (apostrophe française) | **oui** |
| `wi-fi -- invité` | **oui** |
| `order by date` | **oui** |

Les termes de recherche de `traffic.py` (`battery`, `email`, `phone`, `access`, `vpn`, `screen`)
ne contiennent aucun de ces motifs : **le run principal affichera 0 faux positif pour 100200
sans que la règle soit réellement fiable**. C'est une limite de la mesure, à écrire telle
quelle dans la conclusion. Pour la documenter, faire un run complémentaire, séparé et
reproductible (section 6).

## 5. Résultats : run de trafic normal

### 5.1 Données du run

| | |
|---|---|
| Début / fin (UTC) | _à remplir_ |
| Durée réelle | _à remplir_ |
| Requêtes envoyées | _à remplir_ |
| Fautes de mot de passe simulées | _à remplir_ |
| Alertes totales dans la fenêtre | _à remplir_ |

### 5.2 Alertes par règle et qualification

| Règle | Niveau | Alertes | Classification | Justification | Action |
|---|---|---|---|---|---|
| 100000 | 5 | _à remplir_ | FP | _ex. : faute de mot de passe simulée (5 % des connexions) ; comportement attendu_ | _ex. : conserver comme règle de base, ne pas compter comme alerte de détection_ |
| 100001 | 3 | _à remplir_ | | | |
| 100100 | 10 | _à remplir_ | | | |
| 100200 | 12 | _à remplir_ | | | |
| 100300 | 12 | _à remplir_ | | | |
| autres | | _à remplir_ | | | |

Pour **chaque alerte classée faux positif** : règle, requête ayant déclenché l'alerte (heure,
`source_ip`, endpoint, `message` : fournis par `--details`), cause, correction décidée.

### 5.3 Taux de faux positifs

| Indicateur | Valeur |
|---|---|
| Taux A (toutes alertes ÷ requêtes) | _à remplir_ % |
| Taux B (niveau ≥ 7 ÷ requêtes) | _à remplir_ % |
| Alertes par heure (A / B) | _à remplir_ / _à remplir_ |
| Réconciliation 100000 ↔ fautes simulées | _à remplir_ (doivent être égales) |

## 6. Run complémentaire : cas légitimes « pièges »

Run séparé du run principal (le trafic principal reste inchangé pour rester comparable).
Scénario local, reproductible : un utilisateur légitime fait une recherche avec une apostrophe.

```bash
JAR=$(mktemp); IP="198.51.100.99"
curl -s -o /dev/null -c "$JAR" -H "X-Forwarded-For: $IP" \
  --data "email=jdupont@supportdesk.local&password=User_123" http://localhost:3000/login
curl -s -o /dev/null -b "$JAR" -H "X-Forwarded-For: $IP" \
  --data-urlencode "search=l'imprimante" http://localhost:3000/tickets/search
rm -f "$JAR"
```

| Cas légitime | Alerte attendue (hypothèse) | Alerte observée |
|---|---|---|
| recherche `l'imprimante` | 100200 (FP) | _à remplir_ |
| recherche `wi-fi -- invité` | 100200 (FP) | _à remplir_ |
| _autres cas ajoutés_ | | _à remplir_ |

## 7. Correction et nouvelle mesure

Si au moins une règle déclenche à tort : ajuster le motif ou le seuil, **relancer le même protocole**
(mêmes paramètres et même graine), et conserver les deux résultats.

| Règle | Avant (motif / seuil) | Après (motif / seuil) | FP avant | FP après | Détection toujours validée ? |
|---|---|---|---|---|---|
| _à remplir_ | | | | | _vérifier avec le runbook du scénario_ |

Après toute modification d'une règle, **rejouer le runbook correspondant** pour prouver que
l'attaque est toujours détectée (pas de gain de FP au prix d'un faux négatif).

## 8. Alertes sur trafic d'attaque (vrais positifs)

Données reprises des runbooks du dépôt (`runbooks/01` à `03`), observées en live.

| Scénario | Règle principale | Alertes observées | Classification | Remarque |
|---|---|---|---|---|
| 01 Brute force `/login` | 100100 (niveau 10) | 100000 × 14, 100100 × 1 | VP | 15 échecs de connexion ; les 14 alertes 100000 sont du bruit autour de l'alerte utile |
| 01 (secondaire) | 100101 (niveau 12) | validée en logtest uniquement | non confirmée en live | sensible au timing |
| 02 Injection SQL `/tickets/search` | 100200 (niveau 12) | 100200 × 1 | VP | payload `' OR 1=1--` |
| 02 (secondaire) | 100201 (niveau 7) | non testée en live | non confirmée | besoin de générer des erreurs 500 |
| 03 Path traversal `/kb/view` | 100300 (niveau 12) | 100301 × 2 (100300 a aussi matché) | VP | `doc=../../etc/passwd` |

**Faux négatifs connus ou à tester** : _à remplir_ (par exemple : IP falsifiée via `X-Forwarded-For`, payload encodé, ralentissement sous le seuil de 8 échecs par minute).

## 9. Limites de la mesure

- Trafic **synthétique** : 5 comptes sur 5 IP fixes, pauses de 1 à 5 s, pas de vrais utilisateurs
- Termes de recherche **limités à 6 mots** sans caractère spécial (voir section 4)
- Un seul profil de comportement et un taux de fautes de mot de passe **arbitraire** (5 %)
- Durée courte : un taux de 0 % sur la fenêtre ne prouve pas l'absence de faux positifs en production
- Les alertes de corrélation (100100, 100201) ont une fenêtre d'ignore de Wazuh et une latence d'ingestion qui peuvent décaler les comptages
- `source_ip` est falsifiable (en-tête `X-Forwarded-For`), ce qui vaut aussi pour le trafic simulé

## 10. Conclusion

_À rédiger après la mesure : taux retenu et sa définition, règles corrigées, risques restants._