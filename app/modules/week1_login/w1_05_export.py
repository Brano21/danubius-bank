"""W1-05 - OS command injection via the PDF export (A05).

The vulnerability itself lives in the isolated exporter service
(exporter/app.py) - the only container that yields a shell. This module is just
the in-app proxy: it forwards the user's filename to the exporter and shows the
command output. Because the exporter runs on an internal (no-egress) network
with cap_drop:ALL and holds only FLAG_W1-05, a shell there reaches nothing else.
"""
import requests
from flask import request, render_template, current_app

from . import bp
from ...auth import login_required


@bp.route("/export")
@login_required
def export():
    name = request.args.get("name", "vypis.pdf")
    try:
        r = requests.get(
            current_app.config["EXPORTER_URL"] + "/run",
            params={"name": name},
            timeout=15,
        )
        output = r.text
    except Exception as e:  # noqa: BLE001
        output = "Exporter nedostupny: " + str(e)
    return render_template("export.html", name=name, output=output)
