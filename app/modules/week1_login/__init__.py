"""Week 1 - login, client profile, transaction history.

SKELETON SCAFFOLD ONLY. The routes below are intentionally SAFE placeholders so
the app boots and can be reviewed. The Week-1 vulnerabilities (W1-01 SQLi login
bypass, W1-02 UNION leak, W1-03 stored XSS, W1-04 reflected XSS, W1-05 OS
command injection) will be introduced here, each isolated and marked with a
# VULN: <id> ... comment.
"""
from flask import Blueprint, render_template, request, redirect, url_for

from ...auth import login_user, logout_user, current_client, login_required
from ...db import fetch_one
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


@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("week1.index"))
