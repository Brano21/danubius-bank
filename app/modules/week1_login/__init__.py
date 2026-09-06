"""Week 1 - login, client profile, transaction history.

SKELETON SCAFFOLD ONLY. The routes below are intentionally SAFE placeholders so
the app boots and can be reviewed. The Week-1 vulnerabilities (W1-01 SQLi login
bypass, W1-02 UNION leak, W1-03 stored XSS, W1-04 reflected XSS, W1-05 OS
command injection) will be introduced here, each isolated and marked with a
# VULN: <id> ... comment.
"""
import secrets

from flask import Blueprint, render_template, request, redirect, url_for, session

from ...auth import login_user, logout_user, current_client, login_required
from ...db import fetch_one, fetch_all, get_db
from ...flags import get_flag

bp = Blueprint("week1", __name__)


@bp.route("/")
def index():
    return render_template("index.html", client=current_client())


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    info = ("Registration successful. Log in with your email and password."
            if request.args.get("registered") else None)
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN: W1-01 SQL injection (A05) - the login query is built by string
        # concatenation, so input breaks out of the quotes. A payload in the
        # username field, e.g.  ' OR '1'='1'--  , comments out the password
        # check and matches the first row (client id 1). No parameterization,
        # so a WAF / front-end validation on password length does not help.
        sql = (
            "SELECT id FROM clients WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        row = fetch_one(sql)
        if row:
            login_user(row["id"])
            return redirect(url_for("week1.dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error, info=info)


@bp.route("/register", methods=["GET", "POST"])
def register():
    # Functional registration (like OWASP Juice Shop): email + password twice,
    # no email verification, the account is persisted in the DB. Parameterized
    # (not a target). New users can then log in via /login.
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        p1 = request.form.get("password", "")
        p2 = request.form.get("password2", "")
        if "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email."
        elif len(p1) < 6:
            error = "Password must be at least 6 characters."
        elif p1 != p2:
            error = "Passwords do not match."
        elif fetch_one("SELECT id FROM clients WHERE username = %s", (email,)):
            error = "This email is already registered."
        else:
            cur = get_db().cursor()
            cur.execute(
                "INSERT INTO clients (username, password, full_name, role) "
                "VALUES (%s, %s, %s, 'client') RETURNING id",
                (email, p1, email),
            )
            cid = cur.fetchone()[0]
            iban = "SK" + "".join(secrets.choice("0123456789") for _ in range(22))
            cur.execute(
                "INSERT INTO accounts (client_id, iban, balance, currency, account_limit) "
                "VALUES (%s, %s, 100, 'EUR', 5000) RETURNING id",
                (cid, iban),
            )
            acc_id = cur.fetchone()[0]
            # welcome bonus so a new account is not empty
            cur.execute(
                "INSERT INTO transactions (account_id, amount, currency, counterparty, "
                "note, direction) VALUES (%s, 100, 'EUR', 'Danubius Bank', 'Welcome bonus', 'in')",
                (acc_id,),
            )
            cur.close()
            return redirect(url_for("week1.login", registered=1))
    return render_template("register.html", error=error)


@bp.route("/dashboard")
@login_required
def dashboard():
    client = current_client()
    # The W1-01 flag is emitted by application logic (read from env, never from
    # the DB) only on the FIRST client's dashboard - the account the login
    # bypass lands on. A normal player has no credentials for it; the SQLi is
    # the intended way in.
    accounts = fetch_all(
        "SELECT iban, balance::text AS balance, currency FROM accounts "
        "WHERE client_id = %s ORDER BY id",
        (client["id"],),
    )
    w1_01_flag = get_flag("W1-01") if client["id"] == 1 else None
    return render_template("dashboard.html", client=client, accounts=accounts,
                           w1_01_flag=w1_01_flag)


@bp.route("/transactions")
@login_required
def transactions():
    client = current_client()
    acct = fetch_one(
        "SELECT id FROM accounts WHERE client_id = %s ORDER BY id LIMIT 1",
        (client["id"],),
    )
    acct_id = acct["id"] if acct else 0
    q = request.args.get("q", "")
    # VULN: W1-02 SQL injection (A05), UNION-based. The search term q is
    # concatenated into the query, so a UNION SELECT appends rows from another
    # table - e.g. cards - leaking card numbers. The visible columns are text
    # (amount is cast to text), so a working UNION needs four text columns.
    sql = (
        "SELECT counterparty, amount::text AS amount, note, direction FROM transactions "
        "WHERE account_id = " + str(acct_id) + " "
        "AND counterparty ILIKE '%" + q + "%' "
        "ORDER BY ts DESC"
    )
    # Deliberately NOT wrapped in try/except: a malformed injection raises and
    # surfaces as an HTTP 500 (via the branded error handler), which is the
    # intended error-based signal a tester sees in Burp/ZAP. The generic 500
    # does NOT reveal the DB message (e.g. the UNION column count), so it hints
    # that the field is injectable without spoon-feeding the technique; probing
    # still works by status code (ORDER BY 5 -> 500, ORDER BY 4 -> 200).
    rows = fetch_all(sql)
    return render_template("transactions.html", rows=rows, q=q, client=client)


@bp.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    # Per-render nonce placed in the page (window.__proof). The solve endpoint
    # requires it, so the flag CANNOT be obtained by hitting /search/solved
    # directly - the injected JS must read it from the page and send it back.
    nonce = secrets.token_hex(8)
    session["w1_04_nonce"] = nonce
    solved = session.get("w1_04_solved", False)
    # VULN: W1-04 reflected XSS (A05 / XSS). q is echoed back into the page
    # WITHOUT escaping (search.html renders it with |safe), so a payload like
    #   <img src=x onerror="fetch('/search/solved?n='+window.__proof)">
    # executes in the visitor's browser and completes the task.
    flag = get_flag("W1-04") if solved else None
    return render_template("search.html", q=q, flag=flag, nonce=nonce)


@bp.route("/search/solved")
@login_required
def search_solved():
    # Requires the per-render nonce from the reflected page, so a bare request
    # (e.g. curl GET /search/solved) does NOT hand out the flag - the XSS
    # payload must run in the page, read window.__proof and send it here.
    if request.args.get("n", "") != session.get("w1_04_nonce"):
        return "forbidden", 403
    session["w1_04_solved"] = True
    return get_flag("W1-04")


@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("week1.index"))


# W1-03 stored XSS lives in its own bounded file, registered on this blueprint.
from . import w1_03_stored_xss  # noqa: E402,F401
# W1-05 export proxy (the OS-injection vuln itself is in the exporter service).
from . import w1_05_export  # noqa: E402,F401
