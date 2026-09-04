# Danubius Bank — CTF target

Zámerne zraniteľná banková webová aplikácia pre interný, 4-týždňový CTF /
secure-coding tréning. **Nikdy nenasadzuj do produkčnej ani zdieľanej siete.**

> Stav: **W1–W3 hotové** — 14 zraniteľností, realistické bankové UX, bezpečná
> brána + operátorský dashboard, regresné testy. Týždne sa odomykajú cez `WEEK`
> (1–4). Week 4 (blue-team) je zatiaľ odložený.

## Rýchly štart

```bash
cp .env.example .env                  # uprav flagy / heslá podľa behu
WEEK=3 docker compose up --build      # brána na http://localhost:8080
```

## Predvolené prihlásenie

Aplikácia beží **za bránou** (`http://localhost:8080`). Predvolené (demo) údaje:

| Kde | Meno | Heslo |
|-----|------|-------|
| **Brána — vstup pre hráča** | `tester` | `test123` |
| | `hrac1` | `danubius1` |
| | `hrac2` | `danubius2` |
| **Operátor / dashboard** (`/_gate/admin`) | `admin` | `change-me-admin` |

- Hráčske účty sa spravujú v `gate/players.json`; admin v `.env`
  (`GATE_ADMIN_USER` / `GATE_ADMIN_PASSWORD`).
- **Do samotnej banky** sa hráč po vstupe cez bránu dostane zraniteľnosťou
  **W1-01** (SQLi login bypass): meno `' OR '1'='1'-- `, heslo hocijaké.
  Seedované bankové účty (v `seed/seed.sql`) sú *ciele* úloh, nie prihlásenie.

> ⚠️ **Pred ostrým behom zmeň všetky heslá:** `GATE_ADMIN_PASSWORD`,
> `GATE_SECRET`, hráčske účty v `gate/players.json` aj DB heslo.

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

## Poznámky k úlohám (pre CTFd zadania)

Aplikácia je koncipovaná ako reálny internetbanking: neprihlásený vidí len
verejnú landing page + prihlásenie a verejné vyhľadávanie; bankové funkcie
(prehľad, transakcie, prevody, export, admin) sú až po prihlásení. Preto:

- **W1-03 (stored XSS):** collector útočníka je in-app na `/w1-03/collect/<token>`
  — zámerne **nie je v bankovom menu** (je to nástroj útočníka, nie funkcia banky).
  V zadaní CTFd uveď, že hráč exfiltruje cookie na `/w1-03/collect/<vlastný-token>`
  a výsledok si pozrie tam (alebo cez pomocnú stránku `/collector`). Admin „bot"
  je emulovaný a spustí sa po akcii „Nahlásiť adminovi".
- **W1-04 (reflected XSS):** vyhľadávanie je verejná časť stránky (pred loginom).
- **Admin panel** (`/admin/review`) je v menu iba pre rolu admin; bežný klient sa
  k nemu dostane až po eskalácii (napr. login bypass ako `admin`).

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

`master` je plne zraniteľná. Ku každej zraniteľnosti existuje vetva `fix/<id>` s
jediným commitom; diff `master` ↔ `fix/<id>` je referenčná oprava. Pozri
[fixes/README.md](fixes/README.md) a `secure-coding/weekN.md`.
