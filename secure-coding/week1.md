# Secure coding — Týždeň 1

Pre každú zraniteľnosť: zraniteľný úsek (z `master`), tri otázky, a skrytá
referenčná oprava (z `fix/<id>`). Diff zobrazíš cez `fixes/patches/<id>.patch`.

---

## W1-01 — SQL injection: login bypass (A05 Injection)

### Zraniteľný úsek — `app/modules/week1_login/__init__.py`
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

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou (WAF, validácia dĺžky hesla na frontende)?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W1-01)</summary>

```python
row = fetch_one(
    "SELECT id FROM clients WHERE username = %s AND password = %s",
    (username, password),
)
```
Vstup ide do dotazu ako **dáta**, nie ako súčasť SQL textu, takže nemôže zmeniť
štruktúru dotazu. **Nesprávna oprava** (blacklist — filtrovanie `'` alebo slova
`OR`) prehliadne kódované payloady, `--`/`#` komentáre, iné operátory a rieši len
symptóm, nie miešanie kódu a dát.
</details>

---

## W1-02 — SQL injection: UNION únik kariet (A05 Injection)

### Zraniteľný úsek — `app/modules/week1_login/__init__.py`
```python
sql = (
    "SELECT counterparty, note, direction FROM transactions "
    "WHERE account_id = " + str(acct_id) + " "
    "AND counterparty ILIKE '%" + q + "%' "
    "ORDER BY ts DESC"
)
rows = fetch_all(sql)
```

### Otázky
1. Kde presne je diera a prečo práve `UNION SELECT`?
2. Prečo escapovanie `%` alebo úvodzoviek v `q` nestačí?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W1-02)</summary>

```python
rows = fetch_all(
    "SELECT counterparty, note, direction FROM transactions "
    "WHERE account_id = %s AND counterparty ILIKE %s ORDER BY ts DESC",
    (acct_id, "%" + q + "%"),
)
```
Parametrizácia hodnoty `q` (aj s `%` wildcardmi). **Nesprávna oprava** —
blokovať slovo `UNION` — sa obíde komentármi/inline (`UNI/**/ON`), zmenou
veľkosti písmen, alebo iným typom injekcie (boolean/time-based).
</details>

---

## W1-03 — Stored XSS v poznámke k prevodu (A03 / Injection)

### Zraniteľný úsek — `app/templates/_admin_note.html` (partial admin pohľadu)
```jinja
{{ note | safe }}
```
Poznámka od používateľa sa v administrátorskom pohľade renderuje `| safe`, teda
**bez escapovania**. Emulovaný admin „spustí" payload len ak by ho reálny
prehliadač spustil (neescapovaný `<script>`/`on*=`) — preto escapovanie výstupu
zraniteľnosť reálne zatvára.

### Otázky
1. Prečo je problém výstup, a nie vstup (prečo neblokovať `<script>` pri ukladaní)?
2. Kde všade sa tá istá poznámka zobrazuje a kde treba escapovať?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W1-03)</summary>

```jinja
{{ note }}
```
Escapovanie výstupu (Jinja autoescape) — `<`, `>`, `&`, `"` sa zakódujú, takže
payload sa zobrazí ako text a nespustí. **Nesprávna oprava** — filtrovať vstup
(blacklist `<script>`) — sa obíde (`<img onerror>`, `<svg onload>`, kódovanie) a
láme dáta; escapuje sa **na výstupe**, kontextovo.
</details>

---

## W1-04 — Reflected XSS vo vyhľadávaní (A05 / XSS)

### Zraniteľný úsek — `app/templates/search.html`
```jinja
<p>Vysledky pre: {{ q | safe }}</p>
```

### Otázky
1. V čom sa reflected líši od stored XSS z W1-03?
2. Prečo `| safe` tu nemá čo hľadať?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W1-04)</summary>

```jinja
<p>Vysledky pre: {{ q }}</p>
```
Odstránenie `| safe` → hodnota sa escapuje. **Nesprávna oprava** — escapovať len
`<` — prehliadne atribútové a JS kontexty; treba **kontextové** escapovanie na
výstupe (Jinja autoescape to rieši pre HTML kontext).
</details>

---

## W1-05 — OS command injection v exporte (A05 Injection)

### Zraniteľný úsek — `exporter/app.py`
```python
cmd = "echo 'Priprava PDF exportu vypisu ...'; ls -la /srv/exports/" + name
out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
```

### Otázky
1. Prečo je `shell=True` s konkatenáciou nebezpečné?
2. Prečo escapovanie shellu (úvodzovky okolo `name`) nie je spoľahlivé riešenie?
3. Ako by si to opravil?

<details><summary>Referenčná oprava (fix/W1-05)</summary>

```python
out = subprocess.run(
    ["ls", "-la", "/srv/exports/" + name],
    shell=False, capture_output=True, text=True, timeout=10,
)
```
Bez shellu; `name` je **jeden argv prvok**, takže `;`, `|`, `` ` ``, `&&` sú
obyčajný text, nie príkazy. **Nesprávna oprava** — obaliť `name` do úvodzoviek v
shell reťazci — sa obíde (`$(...)`, `` ` ``, escapované úvodzovky). Navyše vhodné
validovať názov (napr. `os.path.basename`, allowlist znakov) proti path
traversal.
</details>
