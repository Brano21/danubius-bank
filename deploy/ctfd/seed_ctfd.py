#!/usr/bin/env python3
"""Set up CTFd and seed the Danubius Bank challenges.

Idempotent-ish: runs the first-boot CTFd setup (team mode), then creates each
challenge with its flag + hints, and attaches the Week-4 evidence files. Flags are
read from the environment (FLAG_W1_01 … FLAG_W4_05) so CTFd matches the app.

Env:
  CTFD_URL            (default http://localhost:80)
  CTF_NAME            (default "Danubius Bank CTF")
  CTFD_ADMIN_USER / CTFD_ADMIN_PASSWORD   (admin account to create)
  MAX_TEAM_SIZE       (default 3)
  APP_TARGET_URL      (the vulnerable app players attack, e.g. http://<ip>:8080)
  FLAG_W1_01 … FLAG_W4_05

Run on the CTF host after both stacks are up:
  python3 deploy/ctfd/seed_ctfd.py
"""
import json
import os
import re
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
URL = os.environ.get("CTFD_URL", "http://localhost:80").rstrip("/")
CTF_NAME = os.environ.get("CTF_NAME", "Danubius Bank CTF")
ADMIN_USER = os.environ.get("CTFD_ADMIN_USER", "ctfadmin")
ADMIN_PW = os.environ.get("CTFD_ADMIN_PASSWORD", "change-me-admin")
ADMIN_EMAIL = os.environ.get("CTFD_ADMIN_EMAIL", "admin@danubius.local")
MAX_TEAM_SIZE = os.environ.get("MAX_TEAM_SIZE", "3")
APP_TARGET = os.environ.get("APP_TARGET_URL", "http://localhost:8080").rstrip("/")
GATE_PLAYER_USER = os.environ.get("GATE_PLAYER_USER", "tester")
GATE_PLAYER_PW = os.environ.get("GATE_PLAYER_PW", "test123")
POINTS = {"Easy": 100, "Medium": 200, "Hard": 300}

s = requests.Session()


def nonce_from(html):
    m = re.search(r"'csrfNonce':\s*\"([0-9a-fA-F]+)\"", html) or \
        re.search(r'name="nonce"[^>]*value="([0-9a-fA-F]+)"', html)
    return m.group(1) if m else None


def get_nonce(path="/"):
    return nonce_from(s.get(URL + path, timeout=30).text)


def api(method, path, nonce, **kw):
    h = kw.pop("headers", {})
    h["CSRF-Token"] = nonce
    return s.request(method, URL + path, headers=h, timeout=60, **kw)


def setup():
    r = s.get(URL + "/setup", timeout=30, allow_redirects=False)
    if r.status_code in (301, 302) and "setup" not in r.headers.get("Location", ""):
        print("CTFd already set up - skipping wizard.")
        return True
    nonce = nonce_from(r.text)
    if not nonce:
        print("Could not read setup nonce (already set up?).")
        return True
    data = {
        "ctf_name": CTF_NAME,
        "ctf_description": "Danubius Bank - intentionally vulnerable banking CTF.",
        "user_mode": "teams",
        "challenge_visibility": "private",
        "account_visibility": "private",
        "score_visibility": "private",
        "registration_visibility": "public",
        "verify_emails": "false",
        "name": ADMIN_USER,
        "email": ADMIN_EMAIL,
        "password": ADMIN_PW,
        "nonce": nonce,
    }
    r = s.post(URL + "/setup", data=data, timeout=60)
    ok = r.status_code in (200, 302)
    print("Setup:", "ok" if ok else "FAILED (%s)" % r.status_code)
    return ok


def set_team_size(nonce):
    try:
        r = api("PATCH", "/api/v1/configs", nonce, json={"team_size": int(MAX_TEAM_SIZE)})
        print("Team size limit ->", MAX_TEAM_SIZE, "(%s)" % r.status_code)
    except Exception as e:  # noqa: BLE001
        print("WARN team size not set (%s) - set it in Admin > Config." % e)


def gen_w4_bundle():
    out = "/tmp/w4bundle"
    try:
        subprocess.run([sys.executable, os.path.join(REPO, "app/modules/week4_evidence/generate.py"),
                        "--out", out], check=True, env=os.environ, cwd=REPO)
        return out
    except Exception as e:  # noqa: BLE001
        print("WARN could not generate W4 bundle (%s) - W4 files not attached." % e)
        return None


def create_challenge(c, nonce, w4dir):
    flag = os.environ.get(c["flag_env"])
    if not flag:
        print("  SKIP %s: %s not in env" % (c["key"], c["flag_env"]))
        return
    desc = c["description"]
    if c.get("target"):
        desc += ("\n\n**Target:** " + APP_TARGET + "/ — sign in at the gate with `"
                 + GATE_PLAYER_USER + "` / `" + GATE_PLAYER_PW + "`, then register a "
                 "bank account or use the W1-01 login bypass.")
    body = {"name": c["name"], "category": c["category"], "description": desc,
            "value": POINTS[c["difficulty"]], "state": "visible", "type": "standard"}
    r = api("POST", "/api/v1/challenges", nonce, json=body)
    if r.status_code != 200:
        print("  FAIL %s create (%s): %s" % (c["key"], r.status_code, r.text[:120]))
        return
    cid = r.json()["data"]["id"]
    api("POST", "/api/v1/flags", nonce, json={"challenge_id": cid, "content": flag, "type": "static"})
    for hint in c.get("hints", []):
        api("POST", "/api/v1/hints", nonce, json={"challenge_id": cid, "content": hint, "cost": 0})
    nfiles = 0
    if w4dir:
        for fn in c.get("files", []):
            p = os.path.join(w4dir, fn)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    api("POST", "/api/v1/files", nonce, files={"file": (fn, fh)},
                        data={"challenge": cid, "type": "challenge"})
                nfiles += 1
    print("  OK   %s  (%d pts, %d hints, %d files)" %
          (c["key"], POINTS[c["difficulty"]], len(c.get("hints", [])), nfiles))


def main():
    for _ in range(30):
        try:
            if s.get(URL + "/", timeout=10).status_code < 500:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(5)

    if not setup():
        print("Setup failed - aborting."); sys.exit(1)
    nonce = get_nonce("/admin") or get_nonce("/")
    if not nonce:
        print("No CSRF nonce after login - aborting."); sys.exit(1)

    set_team_size(nonce)
    w4dir = gen_w4_bundle()
    challenges = json.load(open(os.path.join(HERE, "challenges.json"), encoding="utf-8"))
    print("Seeding %d challenges:" % len(challenges))
    for c in challenges:
        try:
            create_challenge(c, nonce, w4dir)
        except Exception as e:  # noqa: BLE001
            print("  ERROR %s: %s" % (c["key"], e))
    print("Done. CTFd:", URL, "| target:", APP_TARGET)


if __name__ == "__main__":
    main()
