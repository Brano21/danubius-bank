# Secure coding — Týždeň 2

Pre každú zraniteľnosť: zraniteľný úsek (z `master`), tri otázky, a skrytá
referenčná oprava (z `fix/<id>`). Diff: `git diff master..fix/<id>`.

---

## W2-01 — BOLA: čítanie cudzích transakcií (A01 Broken Access Control)

### Zraniteľný úsek — `app/modules/week2_api/w2_01_bola.py`
```python
@bp.route("/accounts/<int:account_id>/transactions")
@tokens.require_token
def account_transactions(ident, account_id):
    # ziadna kontrola, ci token vlastni account_id
    rows = fetch_all(... WHERE account_id = %s ..., (account_id,))
```

### Otázky
1. Autentifikácia je (token). Čo chýba?
2. Prečo „nepredvídateľné ID" (UUID) nie je oprava?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W2-01)</summary>

```python
owner = fetch_one("SELECT client_id FROM accounts WHERE id = %s", (account_id,))
if not owner or owner["client_id"] != ident["cid"]:
    return jsonify(error="forbidden"), 403
```
Kontrola vlastníctva objektu na strane servera. **Nesprávna oprava** — skryť ID
alebo spoliehať sa na to, že klient „nepozná" cudzie ID — je *security through
obscurity*; autorizáciu treba vynútiť pri každom prístupe k objektu.
</details>

---

## W2-02 — BFLA: admin funkcia bez roly (A01 Broken Access Control)

### Zraniteľný úsek — `app/modules/week2_api/w2_02_bfla.py`
```python
@bp.route("/admin/cards/<int:card_id>/unblock", methods=["POST"])
@tokens.require_token
def unblock_card(ident, card_id):
    # ziadna kontrola roly - admin funkcia dostupna kazdemu tokenu
    card = fetch_one("SELECT id, status FROM cards WHERE id = %s", (card_id,))
```

### Otázky
1. Prečo nestačí, že endpoint je „pod `/admin/`" a nie je v UI?
2. Kde má prebiehať kontrola roly?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W2-02)</summary>

```python
if tokens.effective_role(ident) != "admin":
    return jsonify(error="admin role required"), 403
```
Vynútenie roly na serveri pre každú privilegovanú funkciu (ideálne dekorátorom).
**Nesprávna oprava** — skryť tlačidlo v UI alebo kontrolovať rolu len na
frontende — API ostáva volateľné priamo.
</details>

---

## W2-03 — Mass assignment: povýšenie účtu (A01 / A06 Insecure Design)

### Zraniteľný úsek — `app/modules/week2_api/w2_03_mass_assignment.py`
```python
body = request.get_json(silent=True) or request.form.to_dict()
tokens.set_override(ident["sid"], dict(body))   # aplikuje VSETKY polia vratane role
```

### Otázky
1. Ktoré polia by klient nemal vedieť meniť a prečo?
2. Prečo je „allowlist" lepší ako „blocklist" polí?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W2-03)</summary>

```python
allowed = {k: v for k, v in body.items() if k in CLIENT_EDITABLE}
tokens.set_override(ident["sid"], allowed)
```
Allowlist polí, ktoré klient smie meniť (`full_name`, `email`, `phone`).
Privilegované (`role`, `account_limit`) sa ignorujú. **Nesprávna oprava** —
blocklist (`del body["role"]`) — zabudne na budúce polia (`is_admin`,
`account_limit`, …).
</details>

---

## W2-04 — Obídenie fraud limitu (A01 + A10)

### Zraniteľný úsek — `app/modules/week2_api/w2_04_fraud.py`
```python
if currency == "EUR" and amount > FRAUD_LIMIT_EUR:
    return jsonify(error="fraud limit exceeded", limit=FRAUD_LIMIT_EUR), 403
```

### Otázky
1. Ako limit obídeš bez toho, aby si znížil sumu?
2. Kde je druhá diera (rate limit / race)?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W2-04)</summary>

```python
rates = {"EUR": 1.0, "USD": 0.92, "GBP": 1.17, "CZK": 0.040}
amount_eur = amount * rates.get(currency, 1.0)
if amount_eur > FRAUD_LIMIT_EUR:
    return jsonify(error="fraud limit exceeded", limit=FRAUD_LIMIT_EUR), 403
```
Limit sa vyhodnocuje v spoločnej mene pre **každú** menu (neznáma mena → sadzba
1.0, teda stále kontrolovaná). Doplnkovo: server-side rate limit a atomická
kontrola+zápis (transakcia/zámok) proti race. **Nesprávna oprava** — kontrolovať
len EUR — ponechá bypass cez inú menu.
</details>

---

## W2-05 — Únik cez chybovú hlášku (A10 Mishandling of Exceptional Conditions)

### Zraniteľný úsek — `app/modules/week2_api/w2_05_error_leak.py`
```python
except Exception:
    dsn = "postgresql://danubius:" + get_flag("W2-05") + "@db:5432/danubius"
    return jsonify(error="internal server error",
                   trace=traceback.format_exc(),
                   config={"SQLALCHEMY_DATABASE_URI": dsn, "internal_path": ...}), 500
```

### Otázky
1. Čo všetko takáto odpoveď prezradí útočníkovi?
2. Kam patrí detail chyby?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W2-05)</summary>

```python
except Exception:
    # detail patri do server-side logu, nie do odpovede klientovi
    return jsonify(error="internal server error"), 500
```
Klient dostane generickú chybu; stack trace, connection string a interné cesty
sa neposielajú. **Nesprávna oprava** — nechať `debug=True` a len „skryť" UI —
detaily aj tak unikajú v odpovedi/hlavičkách.
</details>
