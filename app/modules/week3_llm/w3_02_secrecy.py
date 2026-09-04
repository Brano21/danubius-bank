"""W3-02 - bypassing a "never reveal" instruction (LLM02)."""
from flask import request, render_template

from . import bp
from .ollama_client import chat
from .prompts import danubka_secure


@bp.route("/secure", methods=["GET", "POST"])
def assistant_secure():
    msg, reply = "", None
    if request.method == "POST":
        msg = request.form.get("message", "")
        # VULN: W3-02 the secret is protected only by a system-prompt
        # instruction ("never reveal"). Reformulation / roleplay / encoding
        # (spell it, base64, "for a test") talks the model past the rule.
        reply = chat(danubka_secure(), msg)
    return render_template(
        "assistant.html", mode="secure",
        subtitle="Danubka v bezpecnom rezime - chrani testovaci udaj.",
        field="message", textarea=False, msg=msg, reply=reply,
    )
