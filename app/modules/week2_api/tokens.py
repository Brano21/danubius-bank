"""Week 2 API - bearer-token auth helpers (signed, stateless) + a per-session
mutable state store used by the access-control vulns.

The token is SIGNED (itsdangerous) so it cannot be forged, but it is readable
(base64) - players can inspect cid/role. Each token carries a random `sid` so
per-player state (e.g. the W2-03 role escalation) stays isolated even when many
players are logged in as the same client (the Week-1 bypass lands everyone on
client 1). State lives in process memory, never the DB.
"""
import functools
import secrets
import threading

from flask import request, jsonify, current_app
from itsdangerous import URLSafeSerializer, BadSignature

_state_lock = threading.Lock()
_overrides = {}   # sid -> dict of overridden profile fields


def _serializer():
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="api-v1")


def issue_token(cid, role):
    sid = secrets.token_hex(8)
    return _serializer().dumps({"cid": cid, "role": role, "sid": sid})


def parse_token(token):
    try:
        return _serializer().loads(token)
    except BadSignature:
        return None


def current_identity():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return parse_token(auth[7:])


def set_override(sid, data):
    with _state_lock:
        _overrides.setdefault(sid, {}).update(data)


def get_override(sid):
    with _state_lock:
        return dict(_overrides.get(sid, {}))


def effective_role(ident):
    return get_override(ident["sid"]).get("role", ident["role"])


def require_token(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        ident = current_identity()
        if ident is None:
            return jsonify(error="missing or invalid bearer token"), 401
        return view(ident, *args, **kwargs)
    return wrapped
