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
        # SCAFFOLD: safe & parameterized. W1-01 will replace this with a
        # string-concatenated query that is injectable.
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
    return render_template("dashboard.html", client=current_client())


@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("week1.index"))
