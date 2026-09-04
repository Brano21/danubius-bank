"""W2-04 - fraud-limit bypass on transfers (A01 + A10)."""
from flask import jsonify, request

from . import bp, tokens
from ...flags import get_flag

FRAUD_LIMIT_EUR = 5000.0


@bp.route("/transfers", methods=["POST"])
@tokens.require_token
def create_transfer(ident):
    body = request.get_json(silent=True) or request.form.to_dict()
    try:
        amount = float(body.get("amount", 0))
    except (TypeError, ValueError):
        amount = 0.0
    currency = str(body.get("currency", "EUR"))
    to_account = body.get("to_account")
    # VULN: W2-04 (A01/A10). The fraud limit is only enforced for EUR - passing
    # ANY other currency skips the check entirely. The endpoint also has no rate
    # limit, so the check can additionally be raced with concurrent requests.
    if currency == "EUR" and amount > FRAUD_LIMIT_EUR:
        return jsonify(error="fraud limit exceeded", limit=FRAUD_LIMIT_EUR), 403
    resp = {"status": "executed", "to_account": to_account,
            "amount": amount, "currency": currency}
    if amount > FRAUD_LIMIT_EUR:
        resp["flag"] = get_flag("W2-04")   # an over-limit transfer went through
    return jsonify(resp)
