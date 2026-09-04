# Danubius Bank — CTF target

An intentionally vulnerable banking web app for an internal, 4-week CTF /
secure-coding training. **Never deploy it to a production or shared network.**

> Status: **W1–W3 done** — 14 vulnerabilities, realistic bank UX, a secure access
> gate + operator dashboard, and regression tests. Weeks unlock via `WEEK` (1–4).
> Week 4 (blue-team) is deferred for now.

## Quick start

Prerequisites: **Docker Desktop** (running), ~16 GB RAM (for Ollama in week 3).

```bash
cp .env.example .env                  # adjust flags / passwords for your run
WEEK=3 docker compose up --build      # gate on http://localhost:8080
```

## Default login

The app runs **behind a gate** (`http://localhost:8080`). Demo credentials:

| Where | User | Password |
|-------|------|----------|
| **Gate — player entrance** | `tester` | `test123` |
| | `hrac1` | `danubius1` |
| | `hrac2` | `danubius2` |
| **Operator / dashboard** (`/_gate/admin`) | `admin` | `change-me-admin` |

- Player accounts are managed in `gate/players.json`; the admin in `.env`
  (`GATE_ADMIN_USER` / `GATE_ADMIN_PASSWORD`).
- **To get into the bank itself**, a player either **registers** (`/register` —
  email + password, the email is not verified) or uses **W1-01** (SQLi login
  bypass): username `' OR '1'='1'-- `, any password.

> ⚠️ **Before a real run, change every password:** `GATE_ADMIN_PASSWORD`,
> `GATE_SECRET`, the player accounts in `gate/players.json`, and the DB password.

## Reset to a clean vulnerable state

```bash
docker compose down -v && docker compose up --build
```

`-v` wipes the database volume, so `seed/seed.sql` runs again (the seed is
idempotent via fresh-volume init). Note: `-v` also wipes the Ollama model volume,
so the model is re-downloaded on the next start.

## Unlocking weeks

Modules unlock **cumulatively** via `WEEK` (1–4). While a week is locked, its code
is **not registered** at all — its routes do not exist and cannot be reached even
by guessing a URL. Unlock = raise `WEEK` and redeploy.

```bash
WEEK=2 docker compose up --build   # or set WEEK in .env
```

## Flag isolation (hard requirement)

- Flags live **only in env** (`FLAG_<ID>`), never in templates or the DB.
- No SQLi/UNION returns a flag — none exists in any table.
  - **Exception:** W1-02 (masked VIP card number) — a single flag is injected into
    the DB at seed time, as an isolated value, never a shared flag table.
- Locked weeks are not registered → no attack surface.
- **W1-05** (the only shell in the whole CTF) runs in a **separate, isolated
  container** (`internal: true` network, `cap_drop: ALL`) that holds only
  `FLAG_W1_05`. Even full compromise of week 1 yields no flag from weeks 2–4.

### ID → env variable mapping

Variable name = `FLAG_` + the task id with `-` replaced by `_`, upper-cased.
E.g. task `W1-05` → `FLAG_W1_05`. (No hyphens, so env/`.env` stay portable.)

## Task mapping (ID → OWASP → CTFd)

| ID | Vulnerability | OWASP 2025 | CTFd |
|----|---------------|------------|------|
| W1-01 | SQLi — login bypass | A05 Injection | _tbd_ |
| W1-02 | SQLi — UNION card leak | A05 Injection | _tbd_ |
| W1-03 | Stored XSS (transfer note) | A03/Injection | _tbd_ |
| W1-04 | Reflected XSS (search) | A05 (XSS) | _tbd_ |
| W1-05 | OS command injection (export) | A05 Injection | _tbd_ |
| W2-01 | BOLA — foreign transactions | A01 BAC | _tbd_ |
| W2-02 | BFLA — admin function | A01 BAC | _tbd_ |
| W2-03 | Mass assignment — privilege escalation | A01/A06 | _tbd_ |
| W2-04 | IDOR + missing rate limit | A01/A10 | _tbd_ |
| W2-05 | Leak via error message | A10 | _tbd_ |
| W3-01 | Direct prompt injection | LLM01 | _tbd_ |
| W3-02 | Bypassing a secrecy instruction | LLM02 | _tbd_ |
| W3-03 | Indirect prompt injection | LLM01 | _tbd_ |
| W3-04 | Excessive agency | LLM06 | _tbd_ |

## Task notes (for CTFd challenges)

The app is designed like a real bank: a logged-out visitor sees only the public
landing + login/registration; banking features (overview, transactions,
transfers, export, admin) are behind the login. So:

- **W1-03 (stored XSS):** the attacker's collector is in-app at
  `/w1-03/collect/<token>` — deliberately **not** in the bank menu (it is an
  attacker tool, not a bank feature). In the CTFd challenge, state that the player
  exfiltrates the cookie to `/w1-03/collect/<their-token>` and reads it there (or
  via the `/collector` helper page). The admin "bot" is emulated and runs on the
  "Report to admin" action.
- **W1-04 (reflected XSS):** search is behind the bank login; `/search/solved`
  requires a per-render nonce from the page, so a bare request does not hand out
  the flag.
- **Admin panel** (`/admin/review`) is in the menu only for the admin role; a
  regular client reaches it only after escalation (e.g. login bypass as `admin`).

## Structure

```
danubius-bank/
├── docker-compose.yml     # gate + web + db + ollama + exporter
├── .env.example           # WEEK, DB creds, FLAG_* variables, gate settings
├── Dockerfile             # web image (python:3.12-slim)
├── requirements.txt
├── wsgi.py
├── app/
│   ├── __init__.py        # factory + conditional module registration by WEEK
│   ├── config.py db.py auth.py flags.py
│   ├── modules/           # week1_login, week2_api, week3_llm, week4_evidence
│   └── templates/
├── gate/                  # access gate + operator dashboard
├── exporter/              # isolated W1-05 container
├── ollama/                # LLM backend (week 3)
├── seed/seed.sql          # clients, accounts, cards, transactions
├── tests/                 # standalone regression suite (runs via the gate)
├── fixes/patches/         # reference fixes as .patch files
└── secure-coding/weekN.md # vulnerable excerpt + questions + hidden fix
```

## Reference fixes

The `master` branch is fully vulnerable (it is the target). The reference fixes
are stored as patch files in [`fixes/patches/`](fixes/patches/) and explained in
`secure-coding/week1.md`, `week2.md`, `week3.md`. See [SITEMAP.md](SITEMAP.md) for
a route map and [WALKTHROUGH.md](WALKTHROUGH.md) for how to run and solve W1–W3.
