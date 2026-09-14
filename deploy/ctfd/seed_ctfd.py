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
ADMIN_PW = os.environ.get("CTFD_ADMIN_PASSWORD", "")
ADMIN_EMAIL = os.environ.get("CTFD_ADMIN_EMAIL", "admin@danubius.local")
MAX_TEAM_SIZE = os.environ.get("MAX_TEAM_SIZE", "3")
APP_TARGET = os.environ.get("APP_TARGET_URL", "http://localhost:8080").rstrip("/")
POINTS = {"Easy": 100, "Medium": 200, "Hard": 300}
# Hints escalate in price: hint 1 is a cheap nudge, hint 2 a pricier reveal.
# Costs are a % of the challenge value, so the two "Unlock Hint" buttons show
# DIFFERENT numbers - which is how you tell them apart (the cheaper one is hint 1)
# - and CTFd deducts the cost from the team's score (CTF-standard). Default
# 10%/20%: Easy -10 | Medium -20/-40 | Hard -30/-60. Override with
# HINT_COST_PCTS="10,20" (a single value or "0" for free hints also works).
HINT_COST_PCTS = [int(x) for x in os.environ.get("HINT_COST_PCTS", "10,20").split(",")
                  if x.strip() != ""] or [0]

if not ADMIN_PW:
    sys.exit("CTFD_ADMIN_PASSWORD is required (no default). Set it in .env / the "
             "environment before seeding.")

s = requests.Session()


def nonce_from(html):
    m = re.search(r"['\"]csrfNonce['\"]:\s*\"([0-9a-fA-F]+)\"", html) or \
        re.search(r'name="nonce"[^>]*value="([0-9a-fA-F]+)"', html)
    return m.group(1) if m else None


def authed():
    """True if the current session is logged in (admin)."""
    try:
        r = s.get(URL + "/api/v1/users/me", timeout=30)
        return r.status_code == 200 and r.json().get("success")
    except Exception:  # noqa: BLE001
        return False


def login():
    """Log in as the admin via CTFd's form login. Works whether we just ran the
    wizard or CTFd was already set up (or set up by hand). Returns True/False."""
    if authed():
        return True
    page = s.get(URL + "/login", timeout=30)
    nonce = nonce_from(page.text)
    if not nonce:
        return False
    s.post(URL + "/login",
           data={"name": ADMIN_USER, "password": ADMIN_PW, "nonce": nonce},
           timeout=30, allow_redirects=False)
    return authed()


def get_nonce(path="/"):
    return nonce_from(s.get(URL + path, timeout=30).text)


def api(method, path, nonce, **kw):
    h = kw.pop("headers", {})
    h["CSRF-Token"] = nonce
    return s.request(method, URL + path, headers=h, timeout=60, **kw)


def setup_done():
    """True if CTFd's first-boot setup has already been completed. When it has,
    GET /setup 302-redirects away; when it hasn't, it serves the wizard (200)."""
    r = s.get(URL + "/setup", timeout=30, allow_redirects=False)
    if r.status_code in (301, 302):
        return True, ""
    return False, r.text


def setup():
    done, html = setup_done()
    if done:
        print("CTFd already set up - will log in as admin.")
        return True
    nonce = nonce_from(html)
    if not nonce:
        print("FAILED: CTFd is not set up but no setup nonce was found on /setup.")
        return False
    data = {
        "ctf_name": CTF_NAME,
        "ctf_description": "Danubius Bank - intentionally vulnerable banking CTF.",
        "user_mode": "teams",
        "challenge_visibility": "private",
        "account_visibility": "private",
        "score_visibility": "private",
        # Admin-only registration: players do NOT self-register. Create their
        # accounts in Admin -> Users (or CSV import). Those same credentials then
        # work at the app gate, which validates against CTFd.
        "registration_visibility": "private",
        "verify_emails": "false",
        "name": ADMIN_USER,
        "email": ADMIN_EMAIL,
        "password": ADMIN_PW,
        "nonce": nonce,
    }
    s.post(URL + "/setup", data=data, timeout=60, allow_redirects=False)
    # Trust the RESULT, not the POST status: a 200 often means the wizard form was
    # re-rendered with a validation error and setup did NOT complete.
    done, _ = setup_done()
    print("Setup:", "ok" if done else "FAILED (CTFd still reports not configured)")
    return done


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


def existing_challenge_names(nonce):
    """Names of challenges already in CTFd, so re-running doesn't duplicate them."""
    try:
        r = api("GET", "/api/v1/challenges?view=admin", nonce)
        if r.status_code == 200:
            return {c.get("name") for c in r.json().get("data", [])}
    except Exception:  # noqa: BLE001
        pass
    return set()


def create_challenge(c, nonce, w4dir, existing):
    if c["name"] in existing:
        print("  SKIP %s: already exists" % c["key"])
        return
    flag = os.environ.get(c["flag_env"])
    if not flag:
        print("  SKIP %s: %s not in env" % (c["key"], c["flag_env"]))
        return
    desc = c["description"]
    if c.get("target"):
        desc += ("\n\n**Target:** " + APP_TARGET + "/ — sign in at the gate with "
                 "**your own CTFd username and password**, then register a bank "
                 "account or use the W1-01 login bypass.")
    value = POINTS[c["difficulty"]]
    body = {"name": c["name"], "category": c["category"], "description": desc,
            "value": value, "state": "visible", "type": "standard"}
    r = api("POST", "/api/v1/challenges", nonce, json=body)
    if r.status_code != 200:
        print("  FAIL %s create (%s): %s" % (c["key"], r.status_code, r.text[:120]))
        return
    cid = r.json()["data"]["id"]
    api("POST", "/api/v1/flags", nonce, json={"challenge_id": cid, "content": flag, "type": "static"})
    # Hints created in order (CTFd lists them top-to-bottom); each gets an
    # escalating cost so hint 1 (cheaper) is distinguishable from hint 2.
    hint_costs = []
    for i, hint in enumerate(c.get("hints", [])):
        pct = HINT_COST_PCTS[min(i, len(HINT_COST_PCTS) - 1)]
        cost = round(value * pct / 100)
        hint_costs.append(cost)
        api("POST", "/api/v1/hints", nonce,
            json={"challenge_id": cid, "content": hint, "cost": cost})
    nfiles = 0
    if w4dir:
        for fn in c.get("files", []):
            p = os.path.join(w4dir, fn)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    # multipart uploads need the nonce in the FORM DATA (not just
                    # the CSRF-Token header) or CTFd answers 403.
                    r = api("POST", "/api/v1/files", nonce, files={"file": (fn, fh)},
                            data={"challenge": cid, "type": "challenge", "nonce": nonce})
                if r.status_code == 200:
                    nfiles += 1
                else:
                    print("    file %s upload failed (%s)" % (fn, r.status_code))
    hints_str = ("-" + "/-".join(map(str, hint_costs))) if hint_costs else "none"
    print("  OK   %s  (%d pts, hints %s, %d files)" %
          (c["key"], value, hints_str, nfiles))


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
    if not login():
        print("Could not log in as admin (%s) - aborting." % ADMIN_USER); sys.exit(1)
    nonce = get_nonce("/admin") or get_nonce("/")
    if not nonce:
        print("No CSRF nonce after login - aborting."); sys.exit(1)

    set_team_size(nonce)
    w4dir = gen_w4_bundle()
    existing = existing_challenge_names(nonce)
    challenges = json.load(open(os.path.join(HERE, "challenges.json"), encoding="utf-8"))
    print("Seeding %d challenges:" % len(challenges))
    for c in challenges:
        try:
            create_challenge(c, nonce, w4dir, existing)
        except Exception as e:  # noqa: BLE001
            print("  ERROR %s: %s" % (c["key"], e))
    print("Done. CTFd:", URL, "| target:", APP_TARGET)


if __name__ == "__main__":
    main()
