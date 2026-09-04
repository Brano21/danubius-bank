# Regression tests (W1–W3)

They verify that the vulnerabilities **still work** (the flag is still reachable
via each exploit). Run them after any change to catch that you broke something.

The tests go **through the gate** (as a real player), so they also confirm the
gate did not break the exploits.

## Run

```bash
# the app must be running (docker compose up); ideally WEEK=3 so W2/W3 are unlocked
python tests/run_tests.py             # W1 (+ W2/W3 if unlocked)
python tests/run_tests.py --with-llm  # also W3 (slow, the LLM is nondeterministic)
```

- **W1/W2** are deterministic and decide the exit code (`0` = OK, `1` = failure).
- **W3** is best-effort (LLM) — reported and retried, but never fails the suite.

No dependencies — pure Python 3 standard library.

## Configuration (env vars)
- `BASE_URL` (default `http://localhost:8080`)
- `GATE_USER` / `GATE_PASS` (default `tester` / `test123` from `gate/players.json`)

## Use during fixing
After applying a fix from `fixes/patches/<id>.patch`, the matching test should
flip to **FAIL** (the fix closes the vulnerability) — that is expected and
confirms the fix works. On a clean `master`, all (deterministic) tests pass.
