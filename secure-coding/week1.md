# Secure coding — Týždeň 1

Pre každú zraniteľnosť: zraniteľný úsek (výrez z `main` s číslami riadkov), tri
otázky bez okamžitých odpovedí, a skrytá referenčná oprava (výrez z `fix/<id>`).
Výrezy a čísla riadkov sa doplnia po stabilizácii kódu týždňa 1.

---

## W1-01 — SQL injection: login bypass  (A05 Injection)

### Zraniteľný úsek
```
TODO: výrez z app/modules/week1_login/__init__.py (main), s číslami riadkov
```

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou (WAF, validácia na frontende)?
3. Ako by si to opravil?

<details>
<summary>Referenčná oprava</summary>

TODO: výrez z `fix/W1-01` + prečo je parametrizácia správna a čo by blacklist
(napr. filtrovanie `'`) prehliadol.
</details>

---

## W1-02 — SQL injection: UNION únik kariet  (A05 Injection)

### Zraniteľný úsek
```
TODO
```

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou?
3. Ako by si to opravil?

<details>
<summary>Referenčná oprava</summary>

TODO
</details>

---

## W1-03 — Stored XSS v poznámke k prevodu  (A03 / Injection)

### Zraniteľný úsek
```
TODO
```

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou?
3. Ako by si to opravil?

<details>
<summary>Referenčná oprava</summary>

TODO
</details>

---

## W1-04 — Reflected XSS vo vyhľadávaní  (A05 / XSS)

### Zraniteľný úsek
```
TODO
```

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou?
3. Ako by si to opravil?

<details>
<summary>Referenčná oprava</summary>

TODO
</details>

---

## W1-05 — OS command injection v exporte  (A05 Injection)

### Zraniteľný úsek
```
TODO: výrez z exportnej funkcie (subprocess so shell=True / konkatenáciou)
```

### Otázky
1. Kde presne je diera?
2. Prečo to prejde bežnou obranou?
3. Ako by si to opravil?

<details>
<summary>Referenčná oprava</summary>

TODO: `subprocess` bez `shell=True`, argument ako prvok zoznamu, prečo escapovanie
shellu nestačí.
</details>
