"""Week 2 - REST API (A01 Broken Access Control: BOLA/BFLA/mass-assignment,
A10 error handling). Locked until WEEK>=2.

Token entry point: POST /api/v1/login is the SAME intentionally-injectable login
as W1-01, so a player uses  ' OR '1'='1'--  to obtain a low-priv token (client 1)
and then attacks the access controls in the w2_* modules.
"""
from flask import Blueprint, request, jsonify

from . import tokens
from ...db import fetch_one

bp = Blueprint("week2", __name__, url_prefix="/api/v1")


@bp.route("/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    sql = ("SELECT id, role FROM clients WHERE username = '" + username +
           "' AND password = '" + password + "'")
    row = fetch_one(sql)
    if not row:
        return jsonify(error="invalid credentials"), 401
    return jsonify(token=tokens.issue_token(row["id"], row["role"]),
                   client_id=row["id"], role=row["role"])


@bp.route("/me")
@tokens.require_token
def api_me(ident):
    return jsonify(client_id=ident["cid"], role=tokens.effective_role(ident))


# Each vulnerability is in its own bounded file, registered on this blueprint.
from . import (  # noqa: E402,F401
    w2_01_bola,
    w2_02_bfla,
    w2_03_mass_assignment,
    w2_04_fraud,
    w2_05_error_leak,
)
