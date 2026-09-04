"""Session helpers shared across modules.

The login *route* lives in modules/week1_login (that is where the W1-01
SQL-injection bypass will be introduced). This file holds only the session
plumbing and the login_required decorator - the safe, shared parts.
"""
from functools import wraps
from flask import session, redirect, url_for, g

from .db import fetch_one


def login_user(client_id):
    session.clear()
    session["client_id"] = client_id


def logout_user():
    session.clear()


def current_client():
    cid = session.get("client_id")
    if cid is None:
        return None
    if "client" not in g:
        g.client = fetch_one(
            "SELECT id, username, full_name, role, is_vip FROM clients WHERE id = %s",
            (cid,),
        )
    return g.client


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_client() is None:
            return redirect(url_for("week1.login"))
        return view(*args, **kwargs)
    return wrapped
