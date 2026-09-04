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
        # VULN: W2-05 Mishandling of Exceptional Conditions (A10). The error
        # response leaks a full stack trace AND internal config, including a
        # database connection string whose "password" is FLAG_W2-05.
        dsn = "postgresql://danubius:" + get_flag("W2-05") + "@db:5432/danubius"
        return jsonify(
            error="internal server error",
            trace=traceback.format_exc(),
            config={
                "SQLALCHEMY_DATABASE_URI": dsn,
                "internal_path": "/srv/app/modules/week2_api/w2_05_error_leak.py",
            },
        ), 500
