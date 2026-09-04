# Secure coding — Week 2

For each vulnerability: the vulnerable snippet (from `master`), three questions,
and a hidden reference fix (`fixes/patches/<id>.patch`).

---

## W2-01 — BOLA: reading foreign transactions (A01 Broken Access Control)

### Vulnerable snippet — `app/modules/week2_api/w2_01_bola.py`
```python
@bp.route("/accounts/<int:account_id>/transactions")
@tokens.require_token
def account_transactions(ident, account_id):
    # no check that the token owns account_id
    rows = fetch_all(... WHERE account_id = %s ..., (account_id,))
```

### Questions
1. Authentication exists (the token). What is missing?
2. Why is an "unguessable ID" (UUID) not a fix?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W2-01.patch)</summary>

```python
owner = fetch_one("SELECT client_id FROM accounts WHERE id = %s", (account_id,))
if not owner or owner["client_id"] != ident["cid"]:
    return jsonify(error="forbidden"), 403
```
Enforce object ownership server-side. A **wrong fix** — hiding the ID or relying
on the client "not knowing" a foreign ID — is security through obscurity;
authorization must be enforced on every object access.
</details>

---

## W2-02 — BFLA: admin function with no role (A01 Broken Access Control)

### Vulnerable snippet — `app/modules/week2_api/w2_02_bfla.py`
```python
@bp.route("/admin/cards/<int:card_id>/unblock", methods=["POST"])
@tokens.require_token
def unblock_card(ident, card_id):
    # no role check - the admin function is reachable by any token
    card = fetch_one("SELECT id, status FROM cards WHERE id = %s", (card_id,))
```

### Questions
1. Why is it not enough that the endpoint is "under `/admin/`" and not in the UI?
2. Where should the role check happen?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W2-02.patch)</summary>

```python
if tokens.effective_role(ident) != "admin":
    return jsonify(error="admin role required"), 403
```
Enforce the role server-side for every privileged function (ideally with a
decorator). A **wrong fix** — hiding the button in the UI or checking the role
only on the front end — leaves the API directly callable.
</details>

---

## W2-03 — Mass assignment: privilege escalation (A01 / A06 Insecure Design)

### Vulnerable snippet — `app/modules/week2_api/w2_03_mass_assignment.py`
```python
body = request.get_json(silent=True) or request.form.to_dict()
tokens.set_override(ident["sid"], dict(body))   # applies ALL fields incl. role
```

### Questions
1. Which fields should the client not be able to change, and why?
2. Why is an "allowlist" better than a "blocklist" of fields?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W2-03.patch)</summary>

```python
allowed = {k: v for k, v in body.items() if k in CLIENT_EDITABLE}
tokens.set_override(ident["sid"], allowed)
```
Allowlist the fields the client may change (`full_name`, `email`, `phone`).
Privileged ones (`role`, `account_limit`) are ignored. A **wrong fix** — a
blocklist (`del body["role"]`) — forgets future fields (`is_admin`,
`account_limit`, …).
</details>

---

## W2-04 — Fraud-limit bypass (A01 + A10)

### Vulnerable snippet — `app/modules/week2_api/w2_04_fraud.py`
```python
if currency == "EUR" and amount > FRAUD_LIMIT_EUR:
    return jsonify(error="fraud limit exceeded", limit=FRAUD_LIMIT_EUR), 403
```

### Questions
1. How do you bypass the limit without lowering the amount?
2. Where is the second flaw (rate limit / race)?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W2-04.patch)</summary>

```python
rates = {"EUR": 1.0, "USD": 0.92, "GBP": 1.17, "CZK": 0.040}
amount_eur = amount * rates.get(currency, 1.0)
if amount_eur > FRAUD_LIMIT_EUR:
    return jsonify(error="fraud limit exceeded", limit=FRAUD_LIMIT_EUR), 403
```
The limit is evaluated in a common currency for **every** currency (unknown → rate
1.0, still checked). Additionally: a server-side rate limit and an atomic
check+write (transaction/lock) against races. A **wrong fix** — checking only EUR
— leaves the other-currency bypass.
</details>

---

## W2-05 — Leak via error message (A10 Mishandling of Exceptional Conditions)

### Vulnerable snippet — `app/modules/week2_api/w2_05_error_leak.py`
```python
except Exception:
    dsn = "postgresql://danubius:" + get_flag("W2-05") + "@db:5432/danubius"
    return jsonify(error="internal server error",
                   trace=traceback.format_exc(),
                   config={"SQLALCHEMY_DATABASE_URI": dsn, "internal_path": ...}), 500
```

### Questions
1. What does such a response disclose to an attacker?
2. Where does the error detail belong?
3. How would you fix it?

<details><summary>Reference fix (fixes/patches/W2-05.patch)</summary>

```python
except Exception:
    # detail belongs in server-side logs, not the client response
    return jsonify(error="internal server error"), 500
```
The client gets a generic error; the stack trace, connection string and internal
paths are not sent. A **wrong fix** — leaving `debug=True` and only "hiding" the
UI — still leaks the details in the response/headers.
</details>
