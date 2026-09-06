# Secure coding — Week 1

For each vulnerability: the vulnerable snippet (from `master`), three questions,
and a hidden reference fix (`fixes/patches/<id>.patch`).

---

## W1-01 — SQL injection: login bypass (A03 Injection)

### Vulnerable snippet — `app/modules/week1_login/__init__.py`
```python
sql = (
    "SELECT id FROM clients WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
row = fetch_one(sql)
```

### Questions
1. Where exactly is the flaw?
2. Why does it pass a common defense (WAF, front-end password-length validation)?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W1-01.patch)</summary>

```python
row = fetch_one(
    "SELECT id FROM clients WHERE username = %s AND password = %s",
    (username, password),
)
```
Input reaches the query as **data**, never as part of the SQL text, so it cannot
change the query structure. A **wrong fix** (a blacklist — filtering `'` or the
word `OR`) misses encoded payloads, `--`/`#` comments, other operators, and
treats the symptom rather than the mixing of code and data.
</details>

---

## W1-02 — SQL injection: UNION card leak (A03 Injection)

### Vulnerable snippet — `app/modules/week1_login/__init__.py`
```python
sql = (
    "SELECT counterparty, amount::text AS amount, note, direction FROM transactions "
    "WHERE account_id = " + str(acct_id) + " "
    "AND counterparty ILIKE '%" + q + "%' "
    "ORDER BY ts DESC"
)
rows = fetch_all(sql)
```

### Questions
1. Where is the flaw, and why `UNION SELECT` specifically?
2. Why is escaping `%` or quotes in `q` not enough?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W1-02.patch)</summary>

```python
rows = fetch_all(
    "SELECT counterparty, amount::text AS amount, note, direction FROM transactions "
    "WHERE account_id = %s AND counterparty ILIKE %s ORDER BY ts DESC",
    (acct_id, "%" + q + "%"),
)
```
Parameterize the `q` value (including the `%` wildcards). A **wrong fix** —
blocking the word `UNION` — is bypassed with comments/inline (`UNI/**/ON`), case
changes, or a different injection type (boolean/time-based).
</details>

---

## W1-03 — Stored XSS in a transfer note (A03 / Injection)

### Vulnerable snippet — `app/templates/_admin_note.html` (admin-view partial)
```jinja
{{ note | safe }}
```
The user's note is rendered `| safe` — **without escaping** — in the admin view.
The emulated admin "runs" the payload only if a real browser would (unescaped
`<script>`/`on*=`), so escaping the output truly closes the vulnerability.

### Questions
1. Why is the output the problem, not the input (why not block `<script>` on save)?
2. Where else is the same note shown, and where must you escape?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W1-03.patch)</summary>

```jinja
{{ note }}
```
Escape the output (Jinja autoescape) — `<`, `>`, `&`, `"` are encoded, so the
payload is shown as text and does not run. A **wrong fix** — input filtering
(blacklisting `<script>`) — is bypassed (`<img onerror>`, `<svg onload>`,
encoding) and mangles data; escape **on output**, contextually.
</details>

---

## W1-04 — Reflected XSS in search (A03 / XSS)

### Vulnerable snippet — `app/templates/search.html`
```jinja
<p>Results for: {{ q | safe }}</p>
```

### Questions
1. How does reflected differ from the stored XSS in W1-03?
2. Why does `| safe` have no place here?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W1-04.patch)</summary>

```jinja
<p>Results for: {{ q }}</p>
```
Removing `| safe` escapes the value. A **wrong fix** — escaping only `<` — misses
attribute and JS contexts; you need **contextual** output escaping (Jinja
autoescape handles the HTML context).
</details>

---

## W1-05 — OS command injection in export (A03 Injection)

### Vulnerable snippet — `exporter/app.py`
```python
cmd = "echo 'Preparing PDF statement export ...'; ls -la /srv/exports/" + name
out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
```

### Questions
1. Why is `shell=True` with concatenation dangerous?
2. Why is shell escaping (quotes around `name`) not a reliable fix?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W1-05.patch)</summary>

```python
out = subprocess.run(
    ["ls", "-la", "/srv/exports/" + name],
    shell=False, capture_output=True, text=True, timeout=10,
)
```
No shell; `name` is a **single argv element**, so `;`, `|`, `` ` ``, `&&` are
plain text, not commands. A **wrong fix** — wrapping `name` in quotes inside a
shell string — is bypassed (`$(...)`, `` ` ``, escaped quotes). Also validate the
name (e.g. `os.path.basename`, an allowlist of characters) against path traversal.
</details>
