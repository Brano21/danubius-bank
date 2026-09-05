"""Operator-only download page for the Week-4 evidence bundle (WEEK >= 4).

This is a convenience for the operator, NOT a player surface: the bundle embeds
every W4 flag, so the route is gated by a shared secret (WEEK4_KEY, defaulting to
the gate admin password). A wrong/absent key returns 404 to hide its existence.
Players receive the artifacts through CTFd, never from here.
"""
import os

from flask import Blueprint, Response, abort, request
from markupsafe import escape

from .generator import build_zip, get_flags
from . import scenario

bp = Blueprint("week4", __name__)


def _authorized():
    key = os.environ.get("WEEK4_KEY") or os.environ.get("GATE_ADMIN_PASSWORD", "change-me-admin")
    return request.args.get("key", "") == key


@bp.route("/evidence")
def evidence():
    if not _authorized():
        abort(404)
    flags = get_flags()
    key = str(escape(request.args.get("key", "")))
    rows = "".join(
        "<tr><td>" + tid + "</td><td><code>" + str(escape(flags[tid]))
        + "</code></td><td>" + str(escape(loc)) + "</td></tr>"
        for tid, loc in scenario.FLAG_LOCATIONS.items())
    # NOTE: built by concatenation, not %/format - the CSS literal "width:100%"
    # and the "{...}" rules would otherwise be read as format specifiers.
    return (
        "<!doctype html><meta charset=utf-8><title>Week 4 evidence</title>"
        "<style>body{font:14px system-ui;margin:2rem;max-width:820px}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;"
        "padding:6px 8px;text-align:left}code{font-size:12px}</style>"
        "<h1>Week 4 &mdash; evidence bundle (operator)</h1>"
        "<p>Download the bundle and upload the files to CTFd. Set each CTFd "
        "challenge flag to the value shown below (these come from the "
        "<code>FLAG_W4_*</code> environment variables).</p>"
        "<p><a href='/evidence/bundle.zip?key=" + key + "'>"
        "&#8681; danubius_week4_evidence.zip</a></p>"
        "<table><tr><th>Task</th><th>Flag (from env)</th>"
        "<th>Where the investigation finds it</th></tr>" + rows + "</table>"
        "<p style='color:#666'>The sample is a benign training artifact; it performs "
        "no real actions. Analyse it statically.</p>")


@bp.route("/evidence/bundle.zip")
def bundle():
    if not _authorized():
        abort(404)
    return Response(
        build_zip(), mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=danubius_week4_evidence.zip"})
