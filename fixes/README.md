# Reference fixes

The `master` branch is fully vulnerable. The reference fixes are stored as **patch
files** in [`fixes/patches/`](patches/) and explained in detail in
`secure-coding/week1.md`, `week2.md`, `week3.md`.

View / apply a fix:

```bash
cat fixes/patches/W1-01.patch                 # see the fix
git apply --check fixes/patches/W1-01.patch   # verify it applies
git apply fixes/patches/W1-01.patch           # apply on master (closes that vuln)
git checkout -- .                             # revert (master stays vulnerable)
git apply fixes/patches/ALL.patch             # all fixes at once
```

Every fix is **verified** by the regression suite: after applying a fix, the
matching test in `tests/run_tests.py` flips from PASS to FAIL (the vulnerability
is closed) while the others stay PASS. On a clean `master`, all pass.

| ID | Patch | What the fix does |
|----|-------|-------------------|
| W1-01 | `patches/W1-01.patch` | parameterized login query |
| W1-02 | `patches/W1-02.patch` | parameterized search |
| W1-03 | `patches/W1-03.patch` | escaped note output |
| W1-04 | `patches/W1-04.patch` | escaped reflected `q` |
| W1-05 | `patches/W1-05.patch` | `subprocess` without a shell (argv) |
| W2-01 | `patches/W2-01.patch` | object ownership check |
| W2-02 | `patches/W2-02.patch` | admin role check |
| W2-03 | `patches/W2-03.patch` | field allowlist (mass assignment) |
| W2-04 | `patches/W2-04.patch` | limit enforced for every currency |
| W2-05 | `patches/W2-05.patch` | generic error (no leak) |
| W3-01 | `patches/W3-01.patch` | secret kept out of the system prompt |
| W3-02 | `patches/W3-02.patch` | protected value kept out of the LLM context |
| W3-03 | `patches/W3-03.patch` | secret kept out of context (filter = defense in depth) |
| W3-04 | `patches/W3-04.patch` | tool restricted to the caller (least privilege) |
| — | `patches/ALL.patch` | all fixes at once |
