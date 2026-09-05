"""Assemble the Week-4 evidence bundle from the scenario + flag values.

Flag values come from the environment (FLAG_W4_01 .. FLAG_W4_05); the demo
defaults below are used when a var is unset, so the bundle always generates.
Stdlib only, so this runs standalone (see generate.py) without Flask or the DB.
"""
import hashlib
import io
import os
import zipfile

try:  # package (app) or standalone (tests / CLI)
    from . import scenario
except ImportError:  # pragma: no cover
    import scenario

DEFAULTS = {
    "W4-01": "RPC{demo_w4_01_entry_point}",
    "W4-02": "RPC{demo_w4_02_leak_scope}",
    "W4-03": "RPC{demo_w4_03_lateral_movement}",
    "W4-04": "RPC{demo_w4_04_static_analysis}",
    "W4-05": "RPC{demo_w4_05_c2_reconstruction}",
}


def get_flags(env=None):
    env = env if env is not None else os.environ
    return {tid: env.get("FLAG_" + tid.replace("-", "_"), dflt)
            for tid, dflt in DEFAULTS.items()}


def build_bundle(flags=None):
    """Return {filename: bytes} for every artifact in the bundle."""
    flags = flags or get_flags()
    files = {
        "access.log": scenario.build_access_log(flags).encode(),
        "auth.log": scenario.build_auth_log(flags).encode(),
        "capture.pcap": scenario.build_pcap(flags),
        scenario.SAMPLE_NAME: scenario.build_sample(flags),
        "README-for-players.txt": scenario.build_players_readme(flags).encode(),
    }
    sums = "".join("%s  %s\n" % (hashlib.sha256(b).hexdigest(), n)
                   for n, b in files.items())
    files["sha256sums.txt"] = sums.encode()
    return files


def build_zip(flags=None):
    files = build_bundle(flags)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()
