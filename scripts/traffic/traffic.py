import argparse
import csv
import json
import random
import threading
import time
from collections import Counter
from pathlib import Path

import requests

SEARCH_TERMS = ["battery", "email", "phone", "access", "vpn", "screen"]
KB_DOCS = ["vpn-guide", "password-policy", "badge-access-procedure"]
COMMENTS = ["Merci, je regarde.", "Problème résolu de mon côté.", "Besoin d'infos supplémentaires."]

stats = Counter()
stats_lock = threading.Lock()
log_lock = threading.Lock()


def load_users(path):
    users_path = Path(path)
    if not users_path.exists():
        raise FileNotFoundError(
            f"Fichier utilisateurs introuvable : {users_path}. "
            "Génère-le depuis database/seed.js ou crée-le manuellement."
        )
    with users_path.open() as f:
        users = json.load(f)
    if not users:
        raise ValueError(f"{users_path} est vide : aucun utilisateur à simuler.")
    return users


def record(label):
    with stats_lock:
        stats[label] += 1


def log_request(path_csv, ts, ip, method, path, status, note=""):
    if not path_csv:
        return
    with log_lock:
        with open(path_csv, "a", newline="") as f:
            csv.writer(f).writerow([ts, ip, method, path, status, note])


def pause(rng, lo=1.0, hi=5.0):
    time.sleep(rng.uniform(lo, hi))


def req(session, method, path, base, headers, ip, path_csv, note="", **kw):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    try:
        r = session.request(method, base + path, headers=headers,
                             timeout=10, allow_redirects=False, **kw)
        record(f"{method} {r.status_code}")
        log_request(path_csv, ts, ip, method, path, r.status_code, note)
        return r
    except requests.RequestException as e:
        record("erreur_reseau")
        log_request(path_csv, ts, ip, method, path, "ERR", note)
        print(f"[!] {method} {path} : {e}")
        return None


def user_journey(user, ip, base, deadline, rng, path_csv):
    s = requests.Session()
    h = {"X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0 (SentinelX-NormalTraffic)"}

    while time.time() < deadline:
        typo = rng.random() <= 0.05
        pwd = user["password"] + "x" if typo else user["password"]
        r = req(s, "POST", "/login", base, h, ip, path_csv,
                note="typo_password" if typo else "",
                data={"email": user["email"], "password": pwd})
        if r is None or "error=1" in r.headers.get("Location", ""):
            pause(rng, 2, 6)
            continue

        pause(rng)
        req(s, "GET", "/dashboard", base, h, ip, path_csv)
        pause(rng)
        req(s, "GET", "/tickets", base, h, ip, path_csv)

        for _ in range(rng.randint(1, 4)):
            pause(rng)
            action = rng.choices(["view", "search", "comment", "kb", "profile"],
                                  weights=[40, 20, 10, 20, 10])[0]
            if action == "view":
                req(s, "GET", f"/tickets/{rng.randint(1, 20)}", base, h, ip, path_csv)
            elif action == "search":
                req(s, "POST", "/tickets/search", base, h, ip, path_csv,
                    data={"q": rng.choice(SEARCH_TERMS)})
            elif action == "comment":
                req(s, "POST", f"/tickets/{rng.randint(1, 20)}/comment", base, h, ip, path_csv,
                    data={"content": rng.choice(COMMENTS)})
            elif action == "kb":
                req(s, "GET", "/kb/view", base, h, ip, path_csv,
                    params={"doc": rng.choice(KB_DOCS)})
            elif action == "profile":
                req(s, "POST", "/profile", base, h, ip, path_csv,
                    data={"displayName": "Jean D.", "theme": rng.choice(["light", "dark"])})

        pause(rng)
        req(s, "GET", "/logout", base, h, ip, path_csv)
        pause(rng, 5, 15)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://localhost:3000")
    p.add_argument("--duration", type=int, default=600, help="durée en secondes")
    p.add_argument("--users", type=int, default=5, help="utilisateurs simultanés")
    p.add_argument("--seed", type=int, default=42, help="seed (reproductibilité)")
    p.add_argument("--output", default="", help="fichier CSV de log détaillé")
    p.add_argument("--users-file", default="scripts/traffic/seed_users.json",
                    help="fichier JSON des comptes à simuler")
    a = p.parse_args()

    all_users = load_users(a.users_file)

    if a.output:
        with open(a.output, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "source_ip", "method", "path", "status", "note"])

    deadline = time.time() + a.duration
    threads = []
    for i in range(a.users):
        rng = random.Random(a.seed + i)
        ip = f"198.51.100.{10 + i}"
        user = all_users[i % len(all_users)]
        t = threading.Thread(target=user_journey,
                              args=(user, ip, a.base_url, deadline, rng, a.output),
                              daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("Résumé")
    print(f"Durée : {a.duration}s | Utilisateurs simultanés : {a.users} | "
          f"Comptes disponibles : {len(all_users)} | Seed : {a.seed}")
    for k, v in sorted(stats.items()):
        print(f"{k:20} {v}")
    print(f"Total : {sum(stats.values())}")
    if a.output:
        print(f"Log détaillé : {a.output}")


if __name__ == "__main__":
    main()