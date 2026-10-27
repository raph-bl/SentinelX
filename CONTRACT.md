# CONTRAT TECHNIQUE — Sentinel X

| | |
|---|---|
| **Version** | 0.2 (brouillon) |
| **Statut** | ⚠️ À VALIDER par toute l'équipe avant toute instrumentation |
| **Application** | SupportDesk (Node.js / Express, vues EJS, sessions, SQLite) |
| **Dernière mise à jour** | 2026-10-20 |

Ce document fixe les décisions partagées entre la piste **instrumentation** (app) et la piste **détection** (Wazuh). Toute modification passe par une revue d'équipe et incrémente la version.

## Validation

| Membre | Rôle | Validé |
|---|---|---|
| Rapahel | Instrumentation | ☐ |
| Tara| Détection | ☐ |
| Flauréanne | Monitoring | ☐ |

---

## 1. Décisions ouvertes (à trancher en équipe)

| # | Décision | Proposition par défaut | Alternative |
|---|---|---|---|
| D1 | Détection des échecs d'auth et des accès refusés | **Option A** : tout déduit dans `middleware/logger.js` via `res.on('finish')` (aucune route modifiée) | **Option B** : routes et `middleware/auth.js` posent `res.locals.event_type`, le logger le lit |
| D2 | Destination des logs | stdout **et** fichier `LOG_FILE` dans un volume partagé | stdout seul (lu via `docker logs`) |
| D3 | Ports hôte de Grafana et Wazuh | voir §6 | à ajuster selon les machines |
| D4 | Confiance dans `X-Forwarded-For` | conservée (`trust proxy: true` déjà dans `app.js`), limite documentée en §4.3 | durcir plus tard (bonus) |

---

## 2. Application cible

- Port d'écoute : variable `PORT`, défaut `3000`
- L'authentification repose sur une session (`express-session`) ; l'identifiant de connexion est l'**e-mail**
- Comportements réels vérifiés dans le code :

| Cas | Réponse |
|---|---|
| Login réussi | `302` → `/dashboard` |
| Login raté | `302` → `/login?error=1` (pas de 401) |
| Route protégée sans session | `302` → `/login` |
| `/admin*` par un non-admin | `403` « Accès refusé » |
| Erreur serveur | `500` « Internal server error » (gestionnaire global d'`app.js`) |
| Route ou document introuvable | `404` |

### Endpoints

| Méthode | Chemin | Auth | Fonction |
|---|---|---|---|
| GET | `/` | non | redirige vers `/login` |
| GET | `/login` | non | page de connexion |
| POST | `/login` | non | vérifie e-mail et mot de passe |
| GET | `/logout` | non | détruit la session |
| GET | `/dashboard` | oui | statistiques et tickets récents |
| GET | `/tickets` | oui | liste, filtres, tri |
| POST | `/tickets/search` | oui | recherche (titre, description) |
| GET | `/tickets/:id` | oui | détail et commentaires |
| GET | `/tickets/:id/export` | oui | export texte d'un ticket |
| POST | `/tickets/:id/comment` | oui | ajoute un commentaire |
| GET | `/admin` | admin | page d'administration |
| POST | `/admin/fetch` | admin | récupère le contenu d'une URL fournie |
| GET | `/profile` | oui | profil |
| POST | `/profile` | oui | met à jour nom affiché et thème |
| GET | `/kb` | oui | liste des documents |
| GET | `/kb/view?doc=…` | oui | affiche un document |
| GET | `/metrics` | non | **nouveau** : métriques Prometheus |

---

## 3. Format des logs

- **Une ligne JSON par événement**, objet **plat** (pas d'objet imbriqué), encodage UTF-8, terminé par `\n`
- Aucun retour à la ligne dans les valeurs (garanti par `JSON.stringify`)
- Compatible avec le décodeur JSON natif de Wazuh (`log_format` = `json`)
- Destination (D2) : stdout + fichier `LOG_FILE` (défaut `/var/log/supportdesk/app.log`), dans le volume `app-logs` monté en lecture par Wazuh
- `GET /metrics` n'est **ni loggé ni compté** (bruit du scraping)

### 3.1 Schéma

| Champ | Type | Obligatoire | Description | Exemple |
|---|---|---|---|---|
| `timestamp` | string | oui | ISO 8601 UTC, millisecondes | `2026-10-20T14:32:11.423Z` |
| `level` | string | oui | `INFO`, `WARN` ou `ERROR` | `WARN` |
| `event_type` | string | oui | valeur de la liste fermée (§3.2) | `auth_failure` |
| `source_ip` | string | oui | IP client, voir §4.3 | `203.0.113.42` |
| `user` | string ou `null` | oui | utilisateur concerné, voir §3.3 | `admin@example.com` |
| `endpoint` | string | oui | chemin demandé, **sans** query string | `/tickets/12` |
| `method` | string | oui | méthode HTTP | `POST` |
| `status_code` | integer | oui | code HTTP final | `302` |
| `message` | string | oui | description lisible de l'événement | `Login failed` |
| `query` | string | non | query string brute (`req.originalUrl` après `?`), tronquée | `doc=../../etc/passwd` |
| `body` | string | non | corps de requête sérialisé, mots de passe masqués, tronqué | `{"q":"' OR 1=1--"}` |
| `user_agent` | string | non | en-tête `User-Agent` | `sqlmap/1.8` |
| `response_time_ms` | number | non | durée de traitement | `12.4` |
| `request_id` | string | non | identifiant unique de requête (corrélation, bonus) | `b7f1c2e0-…` |

Les champs non applicables sont **omis** (sauf `user`, mis à `null`).

### 3.2 Liste fermée des `event_type`

Un seul `event_type` par ligne. **Première règle qui correspond, dans l'ordre du tableau.**

| # | `event_type` | `level` | Condition (évaluée à `res.on('finish')`) | `message` |
|---|---|---|---|---|
| 1 | `server_error` | ERROR | `status_code >= 500` ou passage dans le gestionnaire d'erreurs | message de l'erreur (sans stack) |
| 2 | `auth_failure` | WARN | `POST /login` et en-tête `Location` contient `error=1` | `Login failed` |
| 3 | `auth_success` | INFO | `POST /login` et `Location` = `/dashboard` | `Login succeeded` |
| 4 | `logout` | INFO | `GET /logout` | `Logout` |
| 5 | `access_denied` | WARN | `403`, **ou** redirection vers `/login` sans session sur une route protégée (hors `/`, `/login`, `/logout`) | `Forbidden` / `Unauthenticated access` |
| 6 | `admin_fetch` | WARN | `POST /admin/fetch` | `Admin URL fetch` |
| 7 | `ticket_search` | INFO | `POST /tickets/search` | `Ticket search` |
| 8 | `ticket_export` | INFO | `GET /tickets/:id/export` | `Ticket export` |
| 9 | `ticket_view` | INFO | `GET /tickets/:id` | `Ticket view` |
| 10 | `ticket_comment` | INFO | `POST /tickets/:id/comment` | `Ticket comment` |
| 11 | `profile_update` | INFO | `POST /profile` | `Profile update` |
| 12 | `kb_view` | INFO | `GET /kb/view` avec `status_code` 200 | `KB document view` |
| 13 | `not_found` | WARN | `status_code = 404` (dont `/kb/view` d'un document inexistant) | `Not found` |
| 14 | `http_request` | INFO | toute autre requête | `HTTP request` |

> Si D1 = Option B, les lignes 2, 3 et 5 sont posées explicitement par le code des routes ; les valeurs ci-dessus restent identiques.

### 3.3 Champ `user`

| Situation | Valeur |
|---|---|
| Session active | `req.session.username` |
| `auth_failure` | e-mail saisi (`req.body.email`) |
| `auth_success` | `req.session.username` (lu à la fin de la requête) |
| `logout` | `username` capturé **avant** la destruction de la session |
| Pas de session | `null` |

---

## 4. Règles de capture

### 4.1 Masquage et taille
- Tout champ nommé `password` (ou `pass`, `pwd`) dans `body` est remplacé par `"***"`. **Aucun mot de passe en clair dans les logs.**
- `query` et `body` tronqués à `LOG_BODY_MAX` caractères (défaut 1024)

### 4.2 Ne pas altérer les payloads
`query` et `body` sont journalisés **bruts** (pas de décodage, pas de nettoyage) pour que les règles voient les motifs d'attaque (injections SQL, traversée de chemin, SSRF, XSS…). Seul le JSON garantit l'échappement.

### 4.3 `source_ip`
- Valeur : `req.ip` (`trust proxy: true` est déjà actif dans `app.js`), préfixe `::ffff:` retiré
- Sous Docker, un accès direct renvoie l'IP du **bridge** (ex. `172.x.x.x`). Pour les tests, les scripts d'attaque envoient un `X-Forwarded-For` explicite.
- ⚠️ **Limite connue** : l'en-tête `X-Forwarded-For` est contrôlable par le client, donc l'IP peut être falsifiée (rotation d'IP). À traiter en étape 2 / bonus (règle de contournement puis durcissement).

### 4.4 Exemples de lignes

```json
{"timestamp":"2026-10-20T14:32:11.423Z","level":"WARN","event_type":"auth_failure","source_ip":"203.0.113.42","user":"admin@example.com","endpoint":"/login","method":"POST","status_code":302,"message":"Login failed","body":"{\"email\":\"admin@example.com\",\"password\":\"***\"}","user_agent":"curl/8.5.0"}
{"timestamp":"2026-10-20T14:33:02.118Z","level":"INFO","event_type":"ticket_search","source_ip":"203.0.113.42","user":"alice","endpoint":"/tickets/search","method":"POST","status_code":200,"message":"Ticket search","body":"{\"q\":\"' OR 1=1--\"}"}
{"timestamp":"2026-10-20T14:34:40.907Z","level":"WARN","event_type":"admin_fetch","source_ip":"203.0.113.42","user":"admin","endpoint":"/admin/fetch","method":"POST","status_code":200,"message":"Admin URL fetch","body":"{\"url\":\"http://169.254.169.254/\"}"}
```

---

## 5. Métriques `/metrics`

- Endpoint `GET /metrics`, sans authentification, `Content-Type: text/plain; version=0.0.4; charset=utf-8`
- Bibliothèque proposée : `prom-client` (formatage conforme garanti)
- Monté **avant** le logger : non loggé, non compté
- Scrape Prometheus : toutes les **15 s**

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status_code` | requêtes HTTP |
| `http_request_duration_seconds` | histogram | `method`, `route` | durée (buckets : 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5) |
| `app_events_total` | counter | `event_type` | événements applicatifs (mêmes valeurs que §3.2) |
| `process_*`, `nodejs_*` | divers | — | métriques par défaut (`collectDefaultMetrics`) |

**Règles de labels**
- `route` = **motif** de la route (`/tickets/:id`), jamais le chemin réel ; `unmatched` si aucune route ne correspond (évite l'explosion de cardinalité)
- **Jamais** d'IP, d'utilisateur ou de payload en label

---

## 6. Ports et réseaux

| Service | Port conteneur | Port hôte (proposé) |
|---|---|---|
| SupportDesk | 3000 | 3000 |
| Prometheus | 9090 | 9090 |
| Grafana | 3000 | 3001 |
| Wazuh dashboard | 5601 | 443 |
| Wazuh manager (agents / enrôlement / API) | 1514 / 1515 / 514 / 55000 | 1514 / 1515 / 514 / 55000  |
| Wazuh indexer | 9200 | 9200 |

| Réseau | Services |
|---|---|
| `app-net` | SupportDesk, Prometheus, Grafana |
| `wazuh-net` | composants Wazuh (+ accès en lecture au volume `app-logs`) |

| Volume | Usage |
|---|---|
| `app-logs` | logs JSON de l'app, lus par Wazuh |
| `prometheus_data` | Conservation de l'historique des métriques de performances |
| `grafana_data` | Sauvegarde des utilisateurs et de la configuration de l'interface |
| `wazuh-*` | Sauvegarde des alertes, configurations de détection, index de recherche |

---

## 7. Variables d'environnement

| Variable | Service | Défaut | Description |
|---|---|---|---|
| `PORT` | app | `3000` | port d'écoute |
| `SESSION_SECRET` | app | `dev-secret` | secret de session (à changer hors dev) |
| `LOG_FILE` | app | `/var/log/supportdesk/app.log` | fichier de logs JSON |
| `LOG_BODY_MAX` | app | `1024` | taille max de `query` et `body` |
| `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` | Grafana | — | identifiants admin |
| variables Wazuh | Wazuh | — | à compléter par la piste détection |

Les secrets vivent dans `.env` (**non versionné**) ; `.env.example` (versionné) liste les variables sans valeurs sensibles.

---

## 8. Répartition et responsabilités

| Livrable | Responsable |
|---|---|
| `middleware/logger.js` + gestionnaire d'erreurs d'`app.js` | _à compléter_ |
| `/metrics` | Raphael |
| Tests fonctionnels | _à compléter_ |
| Déploiement Wazuh + règles | _à compléter_ |
| Prometheus + Grafana | Flauréanne |
| docker-compose | Flauréanne |

---

## 9. Vérification de la V1 (dry-run)

1. `POST /login` avec un mauvais mot de passe → une ligne `auth_failure` (WARN), mot de passe masqué
2. `POST /login` valide → `auth_success`
3. `GET /admin` en non-admin → `access_denied` (403)
4. Route protégée sans session → `access_denied` (302)
5. `GET /kb/view?doc=inexistant` → `not_found`
6. `GET /metrics` → format Prometheus valide, `app_events_total` incrémenté
7. La ligne apparaît dans Wazuh avec le champ `event_type` visible

## 10. Historique

| Version | Date | Changement |
|---|---|---|
| 0.1 | 2026-10-20 | Brouillon initial |
| 0.2 | 2026-10-27 | Rajout des rôles, modification des ports |
