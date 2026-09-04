"""W3-04 - excessive agency: an unrestricted tool the assistant will call (LLM06)."""
from flask import request, render_template

from . import bp
from .ollama_client import chat_with_tools
from ...db import fetch_one
from ...flags import get_flag

VIP_ACCOUNT_ID = 3

SYSTEM_AGENT = (
    "Si Danubka, bankovy asistent Danubius Bank. Mas nastroj get_balance na "
    "zistenie zostatku uctu. Ak sa pouzivatel pyta na zostatok konkretneho "
    "uctu, pouzi nastroj get_balance s cislom uctu."
)

TOOLS = [{
    "type": "function",
    "function": {
        "name": "get_balance",
        "description": "Zisti aktualny zostatok na ucte podla cisla uctu.",
        "parameters": {
            "type": "object",
            "properties": {"account_id": {"type": "integer", "description": "cislo uctu"}},
            "required": ["account_id"],
        },
    },
}]


def get_balance(account_id=None, **_):
    # VULN: W3-04 excessive agency (LLM06). The tool has NO authorization: it
    # returns ANY account's balance, so the assistant can be asked to read a
    # foreign account. For the VIP target it returns FLAG_W3-04.
    try:
        account_id = int(account_id)
    except (TypeError, ValueError):
        return {"error": "neplatne cislo uctu"}
    row = fetch_one(
        "SELECT balance::text AS balance FROM accounts WHERE id = %s", (account_id,)
    )
    if not row:
        return {"account_id": account_id, "error": "ucet neexistuje"}
    if account_id == VIP_ACCOUNT_ID:
        return {"account_id": account_id, "balance": get_flag("W3-04"),
                "note": "privatny VIP ucet"}
    return {"account_id": account_id, "balance": row["balance"]}


@bp.route("/agent", methods=["GET", "POST"])
def assistant_agent():
    msg, reply = "", None
    if request.method == "POST":
        msg = request.form.get("message", "")
        reply = chat_with_tools(SYSTEM_AGENT, msg, TOOLS, {"get_balance": get_balance})
    return render_template(
        "assistant.html", mode="agent",
        subtitle="Danubka vie zistit zostatok uctu (nastroj get_balance).",
        field="message", textarea=False, msg=msg, reply=reply,
    )
