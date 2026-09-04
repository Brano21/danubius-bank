"""W1-05 exporter - the ONLY container that yields a shell.

Isolated by docker-compose: internal (no-egress) network with no route to db or
ollama, cap_drop:ALL, and only FLAG_W1-05 in its environment. A shell obtained
here reaches nothing else.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    name = request.args.get("name", "vypis.pdf")
    # VULN: W1-05 OS command injection (A05). The user-controlled filename is
    # concatenated into a shell command executed with shell=True, so a payload
    # such as   vypis.pdf; id   or   vypis.pdf; cat /flag   runs arbitrary
    # commands in this container.
    cmd = "echo 'Priprava PDF exportu vypisu ...'; ls -la /srv/exports/" + name
    try:
        out = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        body = out.stdout + out.stderr
    except Exception as e:  # noqa: BLE001
        body = "export error: " + str(e)
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/healthz")
def healthz():
    return "ok"
