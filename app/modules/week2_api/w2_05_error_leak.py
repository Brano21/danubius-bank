"""W2-05 - sensitive data leak via an unhandled exception (A10)."""
import traceback

from flask import jsonify, request

from . import bp, tokens
from ...flags import get_flag


@bp.route("/statements")
@tokens.require_token
def statements(ident):
    account = request.args.get("account", "")
    try:
        acc_id = int(account)   # non-numeric input raises -> "unhandled"
        return jsonify(account=acc_id, statement=[])
    except Exception:
        # FIX W2-05: return a generic error to the client; the detail belongs in
        # server-side logs only. No stack trace, no connection string, no paths.
        return jsonify(error="internal server error"), 500
