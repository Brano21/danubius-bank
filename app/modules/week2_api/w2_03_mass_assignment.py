"""W2-03 - Mass assignment: PATCH /profile applies arbitrary fields (A01/A06)."""
from flask import jsonify, request

from . import bp, tokens
from ...flags import get_flag

CLIENT_EDITABLE = {"full_name", "email", "phone"}   # what SHOULD be allowed


@bp.route("/profile", methods=["PATCH"])
@tokens.require_token
def patch_profile(ident):
    body = request.get_json(silent=True) or request.form.to_dict()
    # VULN: W2-03 mass assignment (A01/A06 Insecure Design). The whole request
    # body is applied to the (per-session) profile with no allowlist, so
    # privileged fields such as `role` or `account_limit` - which are NOT in
    # CLIENT_EDITABLE - can be set by the client.
    tokens.set_override(ident["sid"], dict(body))
    return jsonify(updated=list(body.keys()),
                   profile=tokens.get_override(ident["sid"]),
                   effective_role=tokens.effective_role(ident))


@bp.route("/admin/portal")
@tokens.require_token
def admin_portal(ident):
    if tokens.effective_role(ident) != "admin":
        return jsonify(error="admin role required"), 403
    return jsonify(message="welcome to the admin portal", flag=get_flag("W2-03"))
