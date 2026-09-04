"""Danubius CTF access gate + operator dashboard.

This service sits IN FRONT of the vulnerable app and is the only published one.
It is intentionally NOT part of the vulnerable surface:

  * Players must authenticate here (accounts issued by the organizer in
    players.json) before any request reaches the target.
  * Every proxied request is logged with the player's real identity - which
    comes from the gate session, NOT from the target's (deliberately broken)
    login. Inside the game a player can still impersonate anyone; the gate
    always knows who they really are.
  * The operator dashboard and its logs live here, in the gate's own SQLite DB,
    so no vulnerability in the target (SQLi, RCE, ...) can read or tamper with
    the monitoring. The target uses a different database entirely.
"""
import datetime
import hmac
import json
import os
import sqlite3
import threading
import time

import requests
from flask import (
    Flask, Response, abort, g, redirect, render_template, request, session, url_for,
)

UPSTREAM = os.environ.get("UPSTREAM_URL", "http://web:8080")
DB_PATH = os.environ.get("GATE_DB", "/data/gate.db")
PLAYERS_FILE = os.environ.get("GATE_PLAYERS_FILE", "/app/players.json")
ADMIN_USER = os.environ.get("GATE_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("GATE_ADMIN_PASSWORD", "change-me-admin")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("GATE_SECRET", "gate-dev-secret")
app.config["SESSION_COOKIE_NAME"] = "gate_session"   # must differ from the app's
# Single strong sign-in in front of ALL of Danubius: a long-lived session,
# valid for 7 days of inactivity, cookie re-issued (slid) at most every 12h.
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=7)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("GATE_COOKIE_SECURE", "0") == "1"

SESSION_MAX_IDLE = 7 * 24 * 3600     # auto-logout after 7 days without a visit
SESSION_REFRESH_AFTER = 12 * 3600    # re-issue (slide) the token every 12 hours

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "content-encoding", "host",
}


def consteq(a, b):
    return hmac.compare_digest(str(a), str(b))


# Basic brute-force protection: lock an IP after too many failures in a window.
_login_lock = threading.Lock()
_login_fails = {}          # ip -> (count, window_start_ts)
LOGIN_MAX_FAILS = 8
LOGIN_WINDOW = 300         # 5 minutes


def _rate_limited(ip):
    with _login_lock:
        cnt, start = _login_fails.get(ip, (0, 0))
        if time.time() - start > LOGIN_WINDOW:
            return False
        return cnt >= LOGIN_MAX_FAILS


def _note_fail(ip):
    with _login_lock:
        cnt, start = _login_fails.get(ip, (0, 0))
        if time.time() - start > LOGIN_WINDOW:
            cnt, start = 0, time.time()
        _login_fails[ip] = (cnt + 1, start or time.time())


def _clear_fails(ip):
    with _login_lock:
        _login_fails.pop(ip, None)


def verify_password(stored, given):
    # Supports werkzeug password hashes (pbkdf2:/scrypt:) or plaintext (dev).
    if isinstance(stored, str) and stored.startswith(("pbkdf2:", "scrypt:")):
        try:
            from werkzeug.security import check_password_hash
            return check_password_hash(stored, given)
        except Exception:
            return False
    return consteq(stored, given)


def load_players():
    try:
        with open(PLAYERS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {p["username"]: p["password"] for p in data}
    except Exception:
        return {}


def init_db():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "CREATE TABLE IF NOT EXISTS requests ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, player TEXT, ip TEXT, "
        "method TEXT, path TEXT, query TEXT, status INTEGER)"
    )
    con.commit()
    con.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_e=None):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def log_request(player, method, path, query, status):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute(
            "INSERT INTO requests (ts,player,ip,method,path,query,status) "
            "VALUES (?,?,?,?,?,?,?)",
            (time.time(), player, request.remote_addr, method, path, query, status),
        )
        con.commit()
        con.close()
    except Exception:
        pass


# --- Gate UI -----------------------------------------------------------------
@app.route("/_gate/login", methods=["GET", "POST"])
def player_login():
    error = None
    nxt = request.values.get("next", "/")
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if _rate_limited(ip):
            error = "Prilis vela pokusov. Skus o chvilu."
        else:
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            players = load_players()
            if u in players and verify_password(players[u], p):
                _clear_fails(ip)
                session.clear()
                session.permanent = True            # 7-day lifetime
                session["player"] = u
                session["seen"] = time.time()
                return redirect(nxt or "/")
            _note_fail(ip)
            error = "Neplatne prihlasovacie udaje."
    return render_template("gate_login.html", error=error, next=nxt)


@app.route("/_gate/logout")
def player_logout():
    session.clear()
    return redirect(url_for("player_login"))


@app.route("/_gate/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if consteq(u, ADMIN_USER) and consteq(p, ADMIN_PASSWORD):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        error = "Neplatne admin udaje."
    return render_template("gate_admin_login.html", error=error)


@app.route("/_gate/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


def _fmt(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


@app.route("/_gate/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))
    con = db()
    recent = [
        {**dict(r), "time": _fmt(r["ts"])}
        for r in con.execute(
            "SELECT ts,player,ip,method,path,query,status FROM requests "
            "ORDER BY id DESC LIMIT 200"
        ).fetchall()
    ]
    summary = [
        {**dict(r), "last_time": _fmt(r["last"])}
        for r in con.execute(
            "SELECT player, COUNT(*) AS c, MAX(ts) AS last FROM requests "
            "GROUP BY player ORDER BY last DESC"
        ).fetchall()
    ]
    total = con.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]
    return render_template("gate_dashboard.html", recent=recent, summary=summary,
                           total=total, players=sorted(load_players()))


# --- Reverse proxy (everything else) -----------------------------------------
@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy(path):
    if path.startswith("_gate"):
        abort(404)
    player = session.get("player")
    if player:
        idle = time.time() - session.get("seen", 0)
        if idle > SESSION_MAX_IDLE:            # 7 days without a visit -> expire
            session.clear()
            player = None
        elif idle > SESSION_REFRESH_AFTER:     # slide the 7-day window every 12h
            session.permanent = True
            session["seen"] = time.time()
    if not player:
        return redirect(url_for("player_login", next=request.full_path))

    qs = request.query_string.decode()
    url = UPSTREAM + "/" + path + (("?" + qs) if qs else "")
    fwd = {k: v for k, v in request.headers if k.lower() not in HOP_BY_HOP}
    fwd["X-Player"] = player   # authoritative identity, for the app's own logs
    try:
        upstream = requests.request(
            request.method, url, data=request.get_data(), headers=fwd,
            allow_redirects=False, timeout=195,
        )
    except requests.RequestException as e:
        log_request(player, request.method, "/" + path, qs, 502)
        return Response("gate: upstream error: " + str(e), status=502)

    log_request(player, request.method, "/" + path, qs, upstream.status_code)

    excluded = HOP_BY_HOP | {"set-cookie"}
    headers = [(k, v) for k, v in upstream.raw.headers.items()
               if k.lower() not in excluded]
    try:
        for sc in upstream.raw.headers.getlist("Set-Cookie"):
            headers.append(("Set-Cookie", sc))
    except AttributeError:
        if "Set-Cookie" in upstream.headers:
            headers.append(("Set-Cookie", upstream.headers["Set-Cookie"]))
    return Response(upstream.content, status=upstream.status_code, headers=headers)
