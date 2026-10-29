# Tests — SupportDesk

## Objectif

Suite de tests fonctionnels couvrant les endpoints critiques de l'application
instrumentée (V1), conformément au CONTRACT.md (§2 comportements, §9 dry-run) et
aux exigences du sujet (« functional test suite covering the critical endpoints,
documented coverage rate »).

## Stack

- **Runner** : `node:test` (natif, Node 20)
- **Client HTTP** : `supertest` (requêtes in-process, sans ouvrir de port)
- **Couverture** : `node --test --experimental-test-coverage` (natif)

## Lancer les tests

Les tests tournent **dans le conteneur** (le module natif `better-sqlite3` est
compilé pour `node:20-alpine`, pas pour le Node de l'hôte) :

```bash
./run_tests.sh                                      # couverture
docker compose run --build --rm supportdesk npm test   # tests seuls
```

> `--build` est nécessaire : `docker compose run` ne reconstruit pas l'image, donc
> sans lui les modifications de code/tests ne sont pas prises en compte.

## Cas couverts (`tests/functional.test.js`)

| # | Test | Attendu | Contrat |
|---|---|---|---|
| 1 | `POST /login` creds valides | `302` → `/dashboard` | §2 login réussi |
| 2 | `POST /login` creds invalides | `302` → `/login?error=1` | §2 login raté |
| 3 | `GET /dashboard` sans session | `302` → `/login` | §2 route protégée |
| 4 | `GET /kb/view?doc=inexistant` (authentifié) | `404` | §2 document introuvable |
| 5 | `GET /metrics` | `200`, `text/plain`, contient `http_requests_total` | §5 métriques |
| 6 | `GET /admin` en non-admin | `403` | §2 accès refusé |
| 7 | Login échoué → **contenu du log** | `event_type=auth_failure`, `level=WARN` | §3.2 ligne 2 |
| 8 | Login réussi → **contenu du log** | `event_type=auth_success`, `level=INFO` | §3.2 ligne 3 |

Les tests 7 et 8 capturent la ligne JSON émise sur `stdout` par le logger et
vérifient que la classification (`event_type`/`level`) distingue bien les deux
issues d'un `POST /login` — toutes deux en `302`, seule l'en-tête `Location` les
sépare.

## Taux de couverture mesuré

Dernière exécution : **8 tests, 0 échec**.

| Fichier | Lignes | Branches | Fonctions |
|---|---|---|---|
| app.js | 77.08 % | 40.00 % | 20.00 % |
| database/db.js | 100.00 % | 100.00 % | 100.00 % |
| database/seed.js | 100.00 % | 75.00 % | 100.00 % |
| middleware/auth.js | 100.00 % | 83.33 % | 100.00 % |
| middleware/logger.js | 84.38 % | 60.00 % | 100.00 % |
| middleware/metrics.js | 100.00 % | 100.00 % | 100.00 % |
| routes/admin.js | 50.00 % | 100.00 % | 0.00 % |
| routes/auth.js | 91.18 % | 80.00 % | 33.33 % |
| routes/kb.js | 74.36 % | 100.00 % | 50.00 % |
| routes/profile.js | 56.52 % | 100.00 % | 0.00 % |
| routes/tickets.js | 21.74 % | 100.00 % | 0.00 % |
| **Global** | **78.16 %** | **72.45 %** | **64.44 %** |

La couverture est volontairement concentrée sur les composants
**sécurité/observabilité** (logger, metrics, auth : 84–100 % lignes). Les routes
métier peu sensibles (`tickets`, `profile`) restent partiellement couvertes et
seront complétées avec les tests non-fonctionnels (étapes 2–3).
