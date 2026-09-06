# Site map — Danubius Bank CTF

Orientation: what is where, what is a **real feature**, a **task target**, an
**attacker tool**, and what authentication is required.

## Layers / services (docker-compose)

```
browser
   │  :8080 (only published port)
   ▼
[ gate ]  ── player sign-in + logging + operator dashboard (outside the vulnerable app)
   │  internal network (proxy)
   ▼
[ web ]  ── Flask "Danubius Bank" (the vulnerable app)
   ├── [ db ]        PostgreSQL (internal)
   ├── [ ollama ]    LLM model for Danubka (internal, W3)
   └── [ exporter ]  isolated container for W1-05 (internal net, cap_drop:ALL)
```

## 1) Gate — `/_gate/*` (security layer, NOT a target)

| Path | What it is | Auth |
|------|------------|------|
| `/_gate/login` | Player sign-in (the single strong login in front of Danubius; 7-day token) | public |
| `/_gate/logout` | Sign out (not needed) | player |
| `/_gate/admin/login` | Operator sign-in | public |
| `/_gate/admin` | **Live dashboard** — player activity (monitoring) | admin |

> Without a gate sign-in, **everything** below is inaccessible (redirect to `/_gate/login`).

## 2) Danubius web — public part (behind the gate, before the bank login)

| Path | What it is | Task |
|------|------------|------|
| `/` | Landing (marketing) / portal home after login | — |
| `/login` | **Bank login** | **target W1-01** (SQLi bypass) |
| `/register` | **Registration** (email + 2× password, no verification; account saved) | real feature (surface for testing) |
| `/collector` | Helper: enter a token → your collector | attacker tool (W1-03) |
| `/w1-03/collect/<token>` | Attacker collector (captured data) | attacker tool (W1-03) |

## 3) Danubius web — portal (after the bank login)

| Path | What it is | Task |
|------|------------|------|
| `/dashboard` | Account overview | **flag W1-01** shown here (client id 1) |
| `/transactions` | Transaction search | **target W1-02** (UNION SQLi) |
| `/search` | Site search (behind login) | **target W1-04** (Reflected XSS) |
| `/search/solved` | W1-04 mechanism — needs a page nonce (bare GET gives no flag) | (W1-04) |
| `/transfer` | New transfer (*Note* field) | **target W1-03** (Stored XSS) |
| `/w1-03/report/<id>` | "Report to admin" → emulated admin | W1-03 mechanism |
| `/admin/review` | Admin transfer review (renders the note **unescaped**) | **sink W1-03**; admin role only |
| `/export` | Statement export to PDF (proxied to the exporter) | **target W1-05** (OS injection) |
| `/logout` | Sign out of the bank | — |

## 4) REST API — `/api/v1/*` (WEEK ≥ 2, token auth)

| Path | Method | Task |
|------|--------|------|
| `/api/v1/login` | POST | issues a token (same injection as W1-01) |
| `/api/v1/me` | GET | token info |
| `/api/v1/accounts/{id}/transactions` | GET | **W2-01 BOLA** |
| `/api/v1/admin/cards/{id}/unblock` | POST | **W2-02 BFLA** |
| `/api/v1/profile` | PATCH | **W2-03 mass assignment** |
| `/api/v1/admin/portal` | GET | checks the role → flag (W2-03) |
| `/api/v1/transfers` | POST | **W2-04 fraud bypass** (currency) |
| `/api/v1/statements` | GET | **W2-05 error leak** (non-numeric `account`) |

## 5) Danubka assistant — `/assistant/*` (WEEK ≥ 3, behind the gate)

| Path | What it is | Task |
|------|------------|------|
| `/assistant/` | Chat with Danubka | **W3-01** direct injection |
| `/assistant/secure` | "Secure mode" (protected value) | **W3-02** secrecy bypass |
| `/assistant/summarize` | Document summary | **W3-03** indirect injection |
| `/assistant/agent` | Agent with the `get_balance` tool | **W3-04** excessive agency |

## Weekly unlocking (`WEEK`)
- `WEEK=1` → sections 2 and 3 (web, W1)
- `WEEK=2` → + API (4, W2)
- `WEEK=3` → + Danubka (5, W3)
- `WEEK=4` → + blue-team evidence generator (operator-only `/evidence`; W4 is
  offline investigation, not a web attack surface)

A locked week is **not registered** — its paths do not exist.

## Legend
- **task target** = the intentionally vulnerable spot (solved in the CTF)
- **attacker tool** = an exploit helper (not a bank feature) — e.g. the collector
- **real security** = only the gate (`/_gate/*`); the bank `/login` is a target, not a control
