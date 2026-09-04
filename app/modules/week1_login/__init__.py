"""Week 1 - login, client profile, transaction history.

SKELETON SCAFFOLD ONLY. The routes below are intentionally SAFE placeholders so
the app boots and can be reviewed. The Week-1 vulnerabilities (W1-01 SQLi login
bypass, W1-02 UNION leak, W1-03 stored XSS, W1-04 reflected XSS, W1-05 OS
command injection) will be introduced here, each isolated and marked with a
# VULN: <id> ... comment.
"""
from flask import Blueprint, render_template, request, redirect, url_for, session

from ...auth import login_user, logout_user, current_client, login_required
from ...db import fetch_one, fetch_all
from ...flags import get_flag

bp = Blueprint("week1", __name__)


@bp.route("/")
def index():
    return render_template("index.html", client=current_client())


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # FIX W1-01: parameterized query - user input is bound as data, never
        # concatenated into the SQL text, so it cannot alter the query.
        row = fetch_one(
            "SELECT id FROM clients WHERE username = %s AND password = %s",
            (username, password),
        )
        if row:
            login_user(row["id"])
            return redirect(url_for("week1.dashboard"))
        error = "Nespravne prihlasovacie udaje."
    return render_template("login.html", error=error)


@bp.route("/dashboard")
@login_required
def dashboard():
    client = current_client()
    # The W1-01 flag is emitted by application logic (read from env, never from
    # the DB) only on the FIRST client's dashboard - the account the login
    # bypass lands on. A normal player has no credentials for it; the SQLi is
    # the intended way in.
    w1_01_flag = get_flag("W1-01") if client["id"] == 1 else None
    return render_template("dashboard.html", client=client, w1_01_flag=w1_01_flag)


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
    # FIX W1-02: parameterized query; the search term is bound as a value, so a
    # UNION cannot be injected (account_id is a trusted int from the session).
    rows = fetch_all(
        "SELECT counterparty, note, direction FROM transactions "
        "WHERE account_id = %s AND counterparty ILIKE %s ORDER BY ts DESC",
        (acct_id, "%" + q + "%"),
    )
    return render_template("transactions.html", rows=rows, q=q, client=client)


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    solved = session.get("w1_04_solved", False)
    # VULN: W1-04 reflected XSS (A05 / XSS). q is echoed back into the page
    # WITHOUT escaping (search.html renders it with |safe), so a payload such as
    #   <img src=x onerror="fetch('/search/solved')">
    # executes in the visitor's browser.
    flag = get_flag("W1-04") if solved else None
    return render_template("search.html", q=q, flag=flag)


@bp.route("/search/solved")
def search_solved():
    # The predefined payload calls this from the reflected page; a browser that
    # actually executed the injected JS marks the task solved and is shown
    # FLAG_W1-04 on the next search render.
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
