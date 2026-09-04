"""W2-02 - BFLA: admin-only card unblock reachable by any token (A01)."""
from flask import jsonify

from . import bp, tokens
from ...db import fetch_one
from ...flags import get_flag


@bp.route("/admin/cards/<int:card_id>/unblock", methods=["POST"])
@tokens.require_token
def unblock_card(ident, card_id):
    # VULN: W2-02 Broken Function Level Authorization (A01). This is an admin
    # function, but there is NO role check - any valid (non-admin) token can
    # call it and unblock a card that is not theirs.
    card = fetch_one("SELECT id, status FROM cards WHERE id = %s", (card_id,))
    if not card:
        return jsonify(error="card not found"), 404
    resp = {"card_id": card_id, "status": "active", "message": "card unblocked"}
    if tokens.effective_role(ident) != "admin":
        resp["flag"] = get_flag("W2-02")   # a non-admin performed an admin action
    return jsonify(resp)
