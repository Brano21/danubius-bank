# Regression tests (W1–W4)

They verify that the vulnerabilities **still work** (the flag is still reachable
via each exploit). Run them after any change to catch that you broke something.

The W1–W3 tests go **through the gate** (as a real player), so they also confirm
the gate did not break the exploits. The W4 test is **offline**: it generates the
evidence bundle in-process and re-derives all 5 flags by the intended technique
(log grep, pcap stream reassembly, sample deobfuscation) — no running stack needed.

## Run

```bash
# the app must be running (docker compose up); ideally WEEK=3 so W2/W3 are unlocked
python tests/run_tests.py             # W1 (+ W2/W3 if unlocked)
python tests/run_tests.py --with-llm  # also W3 (slow, the LLM is nondeterministic)
python tests/test_week4.py            # W4 (offline) — no Docker required
```

- **W1/W2** are deterministic and decide the exit code (`0` = OK, `1` = failure).
- **W3** is best-effort (LLM) — reported and retried, but never fails the suite.

No dependencies — pure Python 3 standard library.

## Configuration (env vars)
- `BASE_URL` (default `http://localhost:8080`)
- `GATE_USER` / `GATE_PASS` — a **valid CTFd account** (the gate validates logins
  against CTFd). Defaults to `CTFD_ADMIN_USER` / `CTFD_ADMIN_PASSWORD` from the
  environment, so `set -a; . ./.env; set +a` before running is enough. CTFd must
  be up and seeded (the admin account exists) for the gate login to succeed.

## Use during fixing
After applying a fix from `fixes/patches/<id>.patch`, the matching test should
flip to **FAIL** (the fix closes the vulnerability) — that is expected and
confirms the fix works. On a clean `master`, all (deterministic) tests pass.
