# Danubius Bank — CTF target

Zámerne zraniteľná banková webová aplikácia pre interný, 4-týždňový CTF /
secure-coding tréning. **Nikdy nenasadzuj do produkčnej ani zdieľanej siete.**

> Stav: **skeleton** — kostra beží (web + db), zraniteľnosti sa dopĺňajú po
> týždňoch (W1 → W4). Aktuálne moduly týždňov 2–4 sú uzamknuté.

## Rýchly štart

```bash
cp .env.example .env          # uprav flagy / heslá podľa behu
docker compose up --build     # web na http://localhost:8080
```

## Reset do čistého zraniteľného stavu

```bash
docker compose down -v && docker compose up --build
```

`-v` zmaže volume databázy, takže `seed/seed.sql` sa spustí nanovo (seed je
idempotentný cez fresh-volume init).

## Odomykanie týždňov

Moduly sa odomykajú **kumulatívne** cez premennú `WEEK` (1–4). Kým je týždeň
uzamknutý, jeho kód sa v aplikácii **vôbec nezaregistruje** — routy neexistujú,
nedajú sa osloviť ani uhádnutím URL. Odomknutie = zvýšiť `WEEK`, doplniť flagy
daného týždňa do `web` služby a redeploy.

```bash
WEEK=2 docker compose up --build   # alebo nastav WEEK v .env
```

## Izolácia flagov (tvrdá požiadavka)

- Flagy sú **iba v env** (`FLAG_<ID>`), nikdy nie v šablónach ani v DB.
- Žiadny SQLi/UNION nevráti flag — v tabuľkách žiadny nie je.
  - **Výnimka:** W1-02 (maskované číslo VIP karty) — jeden flag je vložený do DB
    pri seede, ako izolovaná hodnota, nikdy nie spoločná tabuľka flagov.
- Vypnuté týždne nie sú zaregistrované → neexistujúca plocha útoku.
- **W1-05** (jediný shell v celom CTF) beží v **samostatnom, izolovanom
  kontajneri** (`internal: true` sieť, `cap_drop: ALL`), ktorý má v env **len
  `FLAG_W1_05`**. Ani plná kompromitácia týždňa 1 nevydá flag z týždňov 2–4.

### Mapovanie ID → env premenná

Názov premennej = `FLAG_` + ID úlohy s `-` nahradeným za `_`, veľkými písmenami.
Napr. úloha `W1-05` → `FLAG_W1_05`. (Bez pomlčiek, nech sú env/`.env` prenosné.)

## Mapovanie úloh (ID → OWASP → CTFd)

| ID | Zraniteľnosť | OWASP 2025 | CTFd |
|----|--------------|------------|------|
| W1-01 | SQLi — login bypass | A05 Injection | _tbd_ |
| W1-02 | SQLi — UNION únik kariet | A05 Injection | _tbd_ |
| W1-03 | Stored XSS (poznámka k prevodu) | A03/Injection | _tbd_ |
| W1-04 | Reflected XSS (vyhľadávanie) | A05 (XSS) | _tbd_ |
| W1-05 | OS command injection (export) | A05 Injection | _tbd_ |
| W2-01 | BOLA — cudzie transakcie | A01 BAC | _tbd_ |
| W2-02 | BFLA — admin funkcia | A01 BAC | _tbd_ |
| W2-03 | Mass assignment — povýšenie | A01/A06 | _tbd_ |
| W2-04 | IDOR + chýbajúci rate limit | A01/A10 | _tbd_ |
| W2-05 | Únik cez chybovú hlášku | A10 | _tbd_ |
| W3-01 | Priama prompt injection | LLM01 | _tbd_ |
| W3-02 | Obídenie inštrukcie o mlčaní | LLM02 | _tbd_ |
| W3-03 | Nepriama prompt injection | LLM01 | _tbd_ |
| W3-04 | Excessive agency | LLM06 | _tbd_ |
| W4-01 | Vstupný bod (log analýza) | A09 | _tbd_ |
| W4-02 | Rozsah úniku | A09 | _tbd_ |
| W4-03 | Časová os lateral movementu | A09 | _tbd_ |
| W4-04 | Statická analýza vzorky | — | _tbd_ |
| W4-05 | Malware report (human-graded) | — | _tbd_ |

## Štruktúra

```
danubius-bank/
├── docker-compose.yml     # web + db (+ ollama v3, exporter vo W1-05)
├── .env.example           # WEEK, DB creds, FLAG_* premenné
├── Dockerfile             # web image (python:3.12-slim)
├── requirements.txt
├── wsgi.py
├── app/
│   ├── __init__.py        # factory + podmienená registrácia modulov podľa WEEK
│   ├── config.py          # feature flagy
│   ├── db.py  auth.py  flags.py
│   ├── modules/           # week1_login, week2_api, week3_llm, week4_evidence
│   └── templates/
├── seed/seed.sql          # klienti, účty, karty, transakcie
├── fixes/README.md        # index referenčných opráv (vetvy fix/*)
└── secure-coding/weekN.md # zraniteľný úsek + otázky + skrytá oprava
```

## Referenčné opravy

`main` je plne zraniteľná. Ku každej zraniteľnosti existuje vetva `fix/<id>` s
jediným commitom; diff `main` ↔ `fix/<id>` je referenčná oprava. Pozri
[fixes/README.md](fixes/README.md) a `secure-coding/weekN.md`.
