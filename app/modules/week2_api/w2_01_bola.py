"""W2-01 - BOLA: read any account's transactions by object id (A01)."""
from flask import jsonify

from . import bp, tokens
from ...db import fetch_all, fetch_one
from ...flags import get_flag

VIP_ACCOUNT_ID = 3   # the "target" whose statement reveals the flag


@bp.route("/accounts/<int:account_id>/transactions")
@tokens.require_token
def account_transactions(ident, account_id):
    # FIX W2-01: enforce object-level authorization - the caller may only read
    # accounts they own, so incrementing the id is rejected (BOLA closed).
    owner = fetch_one("SELECT client_id FROM accounts WHERE id = %s", (account_id,))
    if not owner or owner["client_id"] != ident["cid"]:
        return jsonify(error="forbidden"), 403
    rows = fetch_all(
        "SELECT id, ts::text AS ts, amount::text AS amount, currency, "
        "counterparty, note FROM transactions WHERE account_id = %s ORDER BY id",
        (account_id,),
    )
    result = [dict(r) for r in rows]
    owner = fetch_one("SELECT client_id FROM accounts WHERE id = %s", (account_id,))
    caller_owns = bool(owner) and owner["client_id"] == ident["cid"]
    # Flag is emitted from env (never stored in the DB) when a foreign VIP
    # account is read across the missing ownership boundary.
    if account_id == VIP_ACCOUNT_ID and not caller_owns:
        result.append({
            "id": None, "ts": None, "amount": None, "currency": "EUR",
            "counterparty": "PRIVATE-VIP-STATEMENT", "note": get_flag("W2-01"),
        })
    return jsonify(account_id=account_id, transactions=result)
