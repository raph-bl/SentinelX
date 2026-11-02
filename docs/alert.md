# Rapport de qualification des alertes — Sentinel X

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

## 2. Définitions et conventions

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

**Décision de l'équipe : l'indicateur officiel est le Taux B.**

Justification : les règles 100000 et 100001 sont des règles de base qui se déclenchent volontairement à chaque faute de mot de passe ou erreur serveur. Le Taux A compte donc surtout des fautes simulées, et non la qualité de la détection. Il reste publié et réconcilié avec le nombre de fautes simulées, par transparence. Le Taux B est à lire avec les limites de la section 9.

## 3. Protocole de mesure

| Paramètre | Valeur |
|---|---|
| Outil | `scripts/traffic/traffic.py` (Python 3, bibliothèque `requests`) |
| Version du script | commit `55c2f71` — `git status` propre avant la mesure (script gelé) |
| Comptes simulés | `scripts/traffic/seed_users.json` (8 comptes utilisateur du seed) |
| Utilisateurs simultanés | 5 |
| Durée | 600 s |
| Graine aléatoire | 42 |
| IP sources simulées | `198.51.100.10` à `198.51.100.14` (via `X-Forwarded-For`, un utilisateur par IP) |
| Comportement | connexion → dashboard → liste de tickets → 1 à 4 actions (consultation, recherche, commentaire, base de connaissances, profil) → déconnexion ; pauses aléatoires de 1 à 5 s ; **5 % de fautes de mot de passe** par tentative |
| Fenêtre d'analyse | début = 1re requête du CSV ; fin = dernière requête + 30 s |
| Fuseau horaire | UTC (le script écrit l'heure avec `time.gmtime()`) |

### Pré-requis avant de lancer

- [x] Script de trafic committé (`55c2f71`), dépôt propre
- [x] Aucune attaque, aucun test manuel ni autre script en parallèle pendant le run principal (le run « pièges » de la section 6 a été fait **après** l'export des alertes)
- [x] Mêmes paramètres que ceux notés ci-dessus

### Procédure

```bash
# 1. Lancer le trafic (le "Total" est le nombre de requêtes)
python3 scripts/traffic/traffic.py --duration 600 --users 5 --seed 42 --output run.csv

# 2. Attendre ~1 minute (ingestion Wazuh), puis exporter les alertes
docker compose exec -T wazuh.manager cat /var/ossec/logs/alerts/alerts.json > /tmp/alerts_run1.json
```

**3. Comptage.** Les scripts `scripts/traffic/count_alerts.py` et `scripts/traffic/measure_fp.sh`, mentionnés dans la version initiale du modèle, **n'existent pas dans le dépôt**. Le comptage a été fait avec un script Python ad hoc (filtre sur le groupe `supportdesk` et sur la fenêtre d'analyse) :

```python
import json, collections
from datetime import datetime, timezone

start = datetime(2026,11,2,9,51,26,tzinfo=timezone.utc)
end   = datetime(2026,11,2,10,2,11,tzinfo=timezone.utc)
N_REQ, N_TYPO, MIN_LEVEL = 759, 4, 7

rows = []
for line in open('/tmp/alerts_run1.json'):
    try: a = json.loads(line)
    except: continue
    if 'supportdesk' not in a.get('rule',{}).get('groups',[]): continue
    ts = datetime.strptime(a['timestamp'][:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    if start <= ts <= end:
        rows.append((ts, a))

by_rule = collections.Counter((a['rule']['id'], a['rule']['level']) for _, a in rows)
print("Alertes totales :", len(rows))
for (rid, lvl), n in sorted(by_rule.items()):
    print(f"  règle {rid} niveau {lvl} : {n}")
det = sum(n for (r, l), n in by_rule.items() if int(l) >= MIN_LEVEL)
hours = (end - start).total_seconds() / 3600
print(f"Taux A : {len(rows)/N_REQ*100:.2f} %  ({len(rows)/hours:.1f}/h)")
print(f"Taux B : {det/N_REQ*100:.2f} %  ({det/hours:.1f}/h)")
```

## 4. Analyse a priori des règles (hypothèses, confrontées aux mesures aux sections 5 et 6)

| Règle | Niveau | Se déclenche quand | Risque de FP sur trafic normal |
|---|---|---|---|
| 100000 | 5 | chaque `auth_failure` | **Certain par conception** : une faute de mot de passe simulée = une alerte. Nombre attendu = nombre de fautes du CSV. |
| 100001 | 3 | chaque `server_error` (HTTP 5xx) | Faible : le trafic normal ne doit produire aucune erreur 5xx. |
| 100100 | 10 | 8 `auth_failure` en 60 s, même `source_ip` | Très faible : il faudrait 8 fautes consécutives sur une même IP. |
| 100101 | 12 | `auth_success` après 100100 | Nul si 100100 ne se déclenche pas. |
| 100200 | 12 | `ticket_search` dont le `body` contient `union select`, `or 1=1`, `order by`, `--` ou `'` | **Faible sur les termes du script, élevé en usage réel** (section 6). |
| 100201 | 7 | 6 `server_error` en 60 s, même IP | Très faible. |
| 100300 | 12 | `query` contenant `../` ou `%2e%2e` | Faible : les noms de documents normaux n'en contiennent pas. |
| 100301 | 12 | enfant de 100300, fichier sensible dans `query` | Nul sans 100300. |

### Point d'attention : la règle 100200 est large

Le motif de la règle est `(?i)(union\s+select|\bor\b\s+1\s*=\s*1|order\s+by|--|')`. Il contient `'` et `--` seuls.

Les termes de recherche de `traffic.py` (`battery`, `email`, `phone`, `access`, `vpn`, `screen`) ne contiennent aucun de ces motifs : **le run principal affiche 0 alerte 100200 sans que la règle soit réellement fiable**. C'est une limite de la mesure, documentée par le run complémentaire (section 6).

## 5. Résultats : run de trafic normal

### 5.1 Données du run

| | |
|---|---|
| Début / fin (UTC) | 2026-11-02 09:51:26 → 10:01:41 |
| Durée réelle | 10 min 15 s (615 s) |
| Requêtes envoyées | 759 (GET 200 : 418 · GET 302 : 114 · POST 200 : 55 · POST 302 : 172) |
| Fautes de mot de passe simulées | 4 |
| Alertes totales dans la fenêtre | 4 |
| Fenêtre d'analyse | 09:51:26 → 10:02:11 UTC (645 s) |

Le fichier d'alertes exporté contenait 6 lignes. Deux alertes **502** (niveau 3, groupe `ossec`, à 09:29:40 et 09:49:18) sont exclues : elles sont hors groupe `supportdesk` et antérieures au début du run.

### 5.2 Alertes par règle et qualification

| Règle | Niveau | Alertes | Classification | Justification | Action |
|---|---|---|---|---|---|
| 100000 | 5 | 4 | FP attendu | une alerte par faute de mot de passe simulée (4 alertes = 4 fautes du CSV) ; comportement attendu | conserver comme règle de base, ne pas compter comme alerte de détection |
| 100001 | 3 | 0 | n/a | aucun statut 5xx dans le trafic normal | aucune |
| 100100 | 10 | 0 | n/a | 4 fautes en 10 min, seuil : 8 en 60 s | aucune |
| 100200 | 12 | 0 | n/a | aucun motif suspect dans les termes du script (limite : section 9) | voir section 6 |
| 100300 | 12 | 0 | n/a | aucun `../` dans le trafic | aucune |
| autres | | 0 | n/a | les 2 alertes 502 sont hors périmètre | aucune |

Alertes 100000 observées (toutes sur `/login`) : 09:51:26 (IP .11), 09:55:07 (IP .13), 09:55:47 (IP .14), 10:01:23 (IP .12). La première correspond à la première ligne du CSV (`typo_password`, 09:51:26, `198.51.100.11`).

Aucune alerte classée faux positif en dehors de 100000 : pas de fiche détaillée à fournir pour le run principal.

### 5.3 Taux de faux positifs

Base : 759 requêtes, fenêtre d'analyse de 645 s (0,179 h).

| Indicateur | Valeur |
|---|---|
| Taux A (toutes alertes ÷ requêtes) | 4 ÷ 759 = **0,53 %** |
| **Taux B (niveau ≥ 7 ÷ requêtes) — indicateur officiel** | 0 ÷ 759 = **0,00 %** |
| Alertes par heure (A / B) | 22,3 / 0 |
| Réconciliation 100000 ↔ fautes simulées | 4 = 4 ✔ |

## 6. Run complémentaire : cas légitimes « pièges »

Run séparé du run principal (le trafic principal reste inchangé pour rester comparable), lancé **après** l'export des alertes du run principal. Chaque cas utilise une IP dédiée dans la plage `198.51.100.90` à `.99`, donc distincte des IP du trafic normal.

```bash
t() {  # $1 = IP simulée, $2 = terme de recherche
  JAR=$(mktemp)
  curl -s -o /dev/null -c "$JAR" -H "X-Forwarded-For: $1" \
    --data "email=jdupont@supportdesk.local&password=User_123" http://localhost:3000/login
  curl -s -o /dev/null -w "$2: %{http_code}\n" -b "$JAR" -H "X-Forwarded-For: $1" \
    --data-urlencode "search=$2" http://localhost:3000/tickets/search
  rm -f "$JAR"
}
t 198.51.100.98 "wi-fi -- invité"
t 198.51.100.97 "order by date"
t 198.51.100.96 "'"
t 198.51.100.95 "l'imprimante"
t 198.51.100.94 "imprimante"
t 198.51.100.93 "l'a"
t 198.51.100.92 "d'accès badge"
t 198.51.100.91 "x' union select 1,2,3--"
t 198.51.100.90 "a'b"
```

| Cas | Nature | HTTP | Alerte observée |
|---|---|---|---|
| `wi-fi -- invité` | légitime | 200 | **100200 (niveau 12) : FP confirmé** |
| `order by date` | légitime | 200 | **100200 (niveau 12) : FP confirmé** |
| `'` seul | légitime | 200 | **100200 (niveau 12) : FP confirmé** |
| `l'imprimante` (IP .99 et .95) | légitime | **500** | 100001 (niveau 3), **pas de 100200** |
| `l'a`, `d'accès badge`, `a'b` | légitime | **500** | 100001 (niveau 3), **pas de 100200** |
| `vpn`, `imprimante` (contrôles) | légitime | 200 | aucune |
| `x' union select 1,2,3--` | attaque | **500** | 100001 (niveau 3), **pas de 100200** |

Total des alertes de ce run : 10 (3 × 100200 et 7 × 100001, dont 2 proviennent d'un premier test `l'imprimante` lancé deux fois depuis l'IP `.99`).

### Constats

- **Hypothèse de la section 4 confirmée** pour `--`, `order by` et `'` seul : des recherches légitimes déclenchent une alerte de niveau 12.
- **Hypothèse fausse pour l'apostrophe entre lettres** : la recherche plante (HTTP 500) au lieu de déclencher 100200. Dans `middleware/logger.js`, la fonction `classify()` teste `res.statusCode >= 500` **avant** les branches par endpoint : l'événement est journalisé en `server_error` et non en `ticket_search`, donc 100200 ne le voit jamais.
- **Cause des 500** : `routes/tickets.js` (ligne 45) construit la requête par concaténation directe, `WHERE t.title LIKE '%${search}%' OR t.description LIKE '%${search}%'`. Une apostrophe isolée donne une requête syntaxiquement valide (200), alors qu'une apostrophe suivie d'une lettre la casse (500). Cette explication est tirée du code ; le message d'erreur SQL n'a pas été relu.
- La recherche est **injectable** (concaténation directe).

## 7. Correction et nouvelle mesure

**Aucune règle n'a été modifiée pour l'instant.** Il n'y a donc pas de mesure avant/après. Les corrections sont documentées et restent à tester.

| Règle | Avant (motif / seuil) | Après (motif / seuil) | FP avant | FP après | Détection toujours validée ? |
|---|---|---|---|---|---|
| 100200 | `(union\s+select\|\bor\b\s+1\s*=\s*1\|order\s+by\|--\|')` | non modifié | 3 cas légitimes sur 4 motifs testés | n/a | n/a |

### Problèmes identifiés

1. **Faux positifs de 100200** : le motif est trop large (`'`, `--` et `order by` seuls).
2. **Faux négatif** : une injection qui fait planter la requête est journalisée en `server_error` et échappe à 100200.

### Pistes à tester plus tard

- **Resserrer le motif de 100200** avec du contexte, par exemple `union\s+select`, `\bor\b\s+1\s*=\s*1`, `'\s*(or|and)\b`, `'\s*--`, `order\s+by\s+\d`.
- **Ajouter une règle fille de 100001**, limitée à `/tickets/search`, avec un motif strict qui ne matche pas une simple apostrophe (sinon `l'a` redevient un faux positif).
- **Correctif de fond** : paramétrer la requête SQL dans `routes/tickets.js`. Cela supprime à la fois les 500 légitimes et l'injection.

### Après toute modification

Valider avec `wazuh-logtest`, relancer les mêmes cas avec les mêmes IP, puis **rejouer le runbook 02** pour prouver que l'attaque est toujours détectée (pas de gain de FP au prix d'un faux négatif).

## 8. Alertes sur trafic d'attaque (vrais positifs)

Données reprises des runbooks du dépôt (`runbooks/01` à `03`), observées en live.

| Scénario | Règle principale | Alertes observées | Classification | Remarque |
|---|---|---|---|---|
| 01 Brute force `/login` | 100100 (niveau 10) | 100000 × 14, 100100 × 1 | VP | 15 échecs de connexion ; les 14 alertes 100000 sont du bruit autour de l'alerte utile |
| 01 (secondaire) | 100101 (niveau 12) | validée en logtest uniquement | non confirmée en live | sensible au timing |
| 02 Injection SQL `/tickets/search` | 100200 (niveau 12) | 100200 × 1 | VP | payload `' OR 1=1--` |
| 02 (secondaire) | 100201 (niveau 7) | non testée en live | non confirmée | besoin de générer des erreurs 500 |
| 03 Path traversal `/kb/view` | 100300 (niveau 12) | 100301 × 2 (100300 a aussi matché) | VP | `doc=../../etc/passwd` |

### Faux négatifs

- **Prouvé** : `x' union select 1,2,3--` est une vraie tentative d'injection, mais elle renvoie 500 et ne produit que 100001 (niveau 3). Elle n'atteint ni 100200 ni le Taux B. 100201 ne se déclencherait qu'après 6 erreurs en 60 s depuis la même IP.
- **Prouvé** : l'IP source est falsifiable via l'en-tête `X-Forwarded-For` (utilisé pour toutes les IP simulées de ce rapport).
- **Non testés (hypothèses)** : payload encodé, attaque lente sous le seuil de 8 échecs par minute.

## 9. Limites de la mesure

- Trafic **synthétique** : 5 utilisateurs simultanés sur 5 IP fixes, pauses de 1 à 5 s, pas de vrais utilisateurs
- Termes de recherche **limités à 6 mots** sans caractère spécial : le Taux B de 0 % n'est **pas représentatif**, puisque le run complémentaire montre que 100200 se déclenche sur des recherches légitimes
- Un seul profil de comportement et un taux de fautes de mot de passe **arbitraire** (5 % configuré) ; 4 fautes observées sur ce run, avec une graine unique
- Durée courte : un taux de 0 % sur la fenêtre ne prouve pas l'absence de faux positifs en production
- Les alertes de corrélation (100100, 100201) ont une fenêtre d'ignore de Wazuh et une latence d'ingestion qui peuvent décaler les comptages
- `source_ip` est falsifiable (en-tête `X-Forwarded-For`), ce qui vaut aussi pour le trafic simulé
- Le comptage a été fait avec un script ad hoc (`count_alerts.py` et `measure_fp.sh` n'existent pas dans le dépôt)
- La cause exacte des 500 est expliquée par la concaténation SQL, mais le message d'erreur SQL n'a pas été relu
- Les cas de la section 6 sont peu nombreux (9 cas) et ne constituent pas un échantillon représentatif

## 10. Conclusion

Sur 759 requêtes de trafic normal (600 s, 5 utilisateurs, graine 42), le **Taux B officiel est de 0,00 %** et le **Taux A de 0,53 %** (4 alertes 100000, égales aux 4 fautes de mot de passe simulées).

Ce 0 % ne prouve pas la fiabilité de la détection : le run complémentaire montre que la règle 100200 se déclenche à tort sur des recherches légitimes (`--`, `order by`, `'` seul). De plus, une injection qui fait planter la requête (`x' union select 1,2,3--`) échappe à 100200 et ne produit qu'une alerte de niveau 3, hors Taux B.

Aucune règle n'a été modifiée. **Risques restants** :

- faux positifs de 100200 en usage réel
- faux négatifs sur les injections qui provoquent un 500
- IP source falsifiable
- payloads encodés et attaques lentes non testés

Le correctif de fond est de **paramétrer la requête SQL** dans `routes/tickets.js`.