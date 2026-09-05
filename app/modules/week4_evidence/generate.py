"""CLI: generate the Week-4 evidence bundle to a directory.

    # inside the web container (Flask present, any WEEK):
    docker compose exec web python -m app.modules.week4_evidence.generate --out /tmp/w4
    # or standalone from this folder (stdlib only):
    python generate.py --out out

Flag values are read from FLAG_W4_01 .. FLAG_W4_05 (demo defaults otherwise).
"""
import argparse
import os

try:  # package or standalone
    from .generator import build_bundle, get_flags
    from . import scenario
except ImportError:  # pragma: no cover
    from generator import build_bundle, get_flags
    import scenario


def main():
    ap = argparse.ArgumentParser(description="Generate the Danubius Week-4 evidence bundle.")
    ap.add_argument("--out", default="week4_out", help="output directory (created if needed)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    flags = get_flags()
    for name, data in build_bundle(flags).items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(data)

    print("Wrote the evidence bundle to %s/" % args.out)
    print("\nFlag  ->  where the investigation finds it")
    for tid, loc in scenario.FLAG_LOCATIONS.items():
        print("  %-6s %-42s %s" % (tid, flags[tid], loc))
    print("\nUpload the files to CTFd; set each challenge flag to the value above.")


if __name__ == "__main__":
    main()
