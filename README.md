# 🏦 Danubius Bank — CTF & secure-coding training

An **intentionally vulnerable** banking web application for an internal, 4-week
CTF / secure-coding course. Players attack it (Weeks 1–3) and then investigate an
incident (Week 4) — and for every flaw the repo also ships the **defensive code
review** so they learn how to *avoid* it.

> ⚠️ **Never deploy this to a production or shared network.** It is deliberately
> broken. Run it locally or in an isolated lab / cloud account.

**Status — complete:** 14 offensive vulnerabilities (W1–W3) + a 5-task blue-team
investigation (W4), a realistic bank UX, an access **gate** + operator dashboard,
reference fixes for every vuln, and a regression suite. Weeks unlock via `WEEK`.

---

## 📚 Documentation

| Doc | What it is | Use it for |
|-----|------------|------------|
| **[WALKTHROUGH.md](WALKTHROUGH.md)** | **CTFd challenge kit** | Per level: description, hint(s), solve command, flag — paste into CTFd |
| **[TESTING-GUIDE.md](TESTING-GUIDE.md)** | **Black-box methodology** | *How a tester discovers* each flaw, step by step (WSTG-aligned), hands-on |
| **[secure-coding/](secure-coding/)** | **Defensive code review** | *Where the bug is and how to fix it* — the blue-team / secure-coding side |
| **[fixes/patches/](fixes/patches/)** | Reference fixes as `.patch` | See / apply the corrected code for any task |
| **[SITEMAP.md](SITEMAP.md)** | Route & service map | What every URL is (real feature vs. task target vs. attacker tool) |
| [app/modules/week4_evidence/README.md](app/modules/week4_evidence/README.md) | Week-4 generator | Build the evidence bundle for the blue-team challenges |
| [tests/README.md](tests/README.md) | Regression suite | Re-verify every exploit still works after a change |

---

## 🚀 Quick start

Prerequisites: **Docker Desktop** running, ~16 GB RAM (for the Week-3 LLM).

```bash
cp .env.example .env                  # adjust flags / passwords for your run
WEEK=4 docker compose up --build      # full lab (W1–W4); gate on http://localhost:8080
```

The app runs **behind an access gate** at `http://localhost:8080`.

| Where | User | Password |
|-------|------|----------|
| **Gate — player entrance** | `tester` | `test123` |
| | `hrac1` / `hrac2` | `danubius1` / `danubius2` |
| **Operator dashboard** (`/_gate/admin`) | `admin` | `change-me-admin` |

**Into the bank itself:** a player either **registers** (`/register`) or uses the
**W1-01** login bypass (`' OR '1'='1'-- `, any password).

> ⚠️ **Before any shared run, change every secret:** `GATE_ADMIN_PASSWORD`,
> `GATE_SECRET`, `SECRET_KEY`, the accounts in `gate/players.json`, and the DB
> password. `.env` is git-ignored — keep real flags out of git.

---

## 🗓️ Weeks & unlocking

Modules unlock **cumulatively** via `WEEK` (1–4). A locked week's code is **not
registered** — its routes don't exist and can't be reached by guessing a URL.

| `WEEK` | Adds | Tasks |
|:------:|------|-------|
| 1 | Web app | W1-01 … W1-05 |
| 2 | REST API | W2-01 … W2-05 |
| 3 | Danubka AI assistant (Ollama) | W3-01 … W3-04 |
| 4 | Blue-team evidence generator (operator `/evidence`) | W4-01 … W4-05 (offline) |

```bash
WEEK=2 docker compose up --build      # e.g. only through Week 2
```

---

## 🎯 Task map

Difficulty drives CTFd points (**Easy 100 · Medium 200 · Hard 300**). Full
descriptions, hints and solves are in **[WALKTHROUGH.md](WALKTHROUGH.md)**; the
defensive fix of each is in **[secure-coding/](secure-coding/)**.

| ID | Vulnerability | OWASP | Difficulty |
|----|---------------|-------|:----------:|
| W1-01 | SQL injection — login bypass | A03 Injection | Easy |
| W1-02 | UNION SQL injection — card-data leak | A03 Injection | Medium |
| W1-03 | Stored XSS → admin session theft | A03 (XSS) | Hard |
| W1-04 | Reflected XSS | A03 (XSS) | Medium |
| W1-05 | OS command injection | A03 Injection | Easy |
| W2-01 | BOLA / IDOR — foreign account | A01 BAC (API1) | Easy |
| W2-02 | BFLA — admin function | A01 BAC (API5) | Easy |
| W2-03 | Mass assignment → privilege escalation | A01 / A08 (API6) | Hard |
| W2-04 | Business-logic — fraud-limit bypass | A04 Insecure Design | Medium |
| W2-05 | Error-based information disclosure | A05 / A09 | Medium |
| W3-01 | Direct prompt injection | LLM01 | Medium |
| W3-02 | Bypassing a "never reveal" guardrail | LLM01 | Hard |
| W3-03 | Indirect prompt injection (via document) | LLM01 | Hard |
| W3-04 | Excessive agency (tool abuse) | LLM — Excessive Agency | Medium |
| W4-01 | Log triage — entry point | A09 Logging | Easy |
| W4-02 | Breach scope — data leak (pcap) | Forensics | Medium |
| W4-03 | Lateral movement (pcap) | Forensics | Medium |
| W4-04 | Static malware analysis | Forensics | Hard |
| W4-05 | C2 reconstruction (pcap) | Forensics | Hard |

---

## 🛡️ Learn the defense — the built-in code review

Weeks 1–3 are not only about breaking in. For **every** vulnerability the repo
ships a code review so players see *where* the bug is and *how* to avoid it.

**Where it lives:** [`secure-coding/`](secure-coding/) — one file per week
([week1](secure-coding/week1.md) · [week2](secure-coding/week2.md) ·
[week3](secure-coding/week3.md) · [week4](secure-coding/week4.md)). Each entry has:

1. the **vulnerable snippet** (the exact code, from `master`),
2. three **questions** to make you reason,
3. a **Reference fix** — the corrected code + a note on *wrong* fixes.

> 💡 **How to see the fix:** on GitHub the reference fix is a **collapsed toggle** —
> click the grey **“Reference fix (…)”** line under each task to expand the answer.
> (That's why it can look "missing" at first glance — it's hidden until you click.)

**See a fix as a plain diff, or apply it to confirm it closes the vuln:**
```bash
cat fixes/patches/W1-01.patch          # just read the corrected code
git apply fixes/patches/W1-01.patch    # patch the running code…
#   rebuild web and re-run the exploit → it now fails
git checkout -- .                      # …then revert (master stays vulnerable)
git apply fixes/patches/ALL.patch      # or apply every fix at once
```
Every fix is verified by the regression suite: after applying it, that task's test
in `tests/run_tests.py` flips **PASS → FAIL** (the vuln is closed) while the rest
stay PASS.

---

## 🔒 Flag isolation (hard requirement)

- Flags live **only in env** (`FLAG_<ID>`; variable = `FLAG_` + id with `-`→`_`,
  upper-cased, e.g. `W1-05` → `FLAG_W1_05`) — never in templates or the DB.
- No SQLi / UNION returns another task's flag — none exists in any table. *Exception:*
  W1-02 injects one masked VIP card number into the DB at seed time (an isolated
  value, not a shared flag table).
- **W1-05** (the only shell in the whole CTF) runs in a **separate, isolated
  container** (`internal: true` network, `cap_drop: ALL`) holding only `FLAG_W1_05`.
- Verified: SQLi can't read the OS env (`pg_read_file` denied — not superuser), and
  no earlier task leaks a later task's flag.

---

## ♻️ Reset to a clean vulnerable state

```bash
docker compose down -v && docker compose up --build
```
`-v` wipes the DB volume so `seed/seed.sql` re-runs. (It also wipes the Ollama
model volume, so the model re-downloads on next start.)

---

## 🗂️ Structure

```
danubius-bank/
├── docker-compose.yml        # gate + web + db + ollama + exporter
├── .env.example              # WEEK, DB creds, FLAG_* variables, gate settings
├── Dockerfile · wsgi.py · requirements.txt
├── app/
│   ├── __init__.py           # app factory + conditional module registration by WEEK
│   ├── config.py db.py auth.py flags.py
│   ├── modules/              # week1_login · week2_api · week3_llm · week4_evidence
│   └── templates/
├── gate/                     # access gate + operator dashboard (real security)
├── exporter/                 # isolated W1-05 container (the only shell)
├── ollama/                   # LLM backend (Week 3)
├── seed/seed.sql             # clients, accounts, cards, transactions
├── tests/                    # standalone regression suite (runs via the gate)
├── fixes/patches/            # reference fixes as .patch files (+ ALL.patch)
├── secure-coding/weekN.md    # defensive code review: vuln snippet + fix
├── WALKTHROUGH.md            # CTFd challenge kit
├── TESTING-GUIDE.md          # black-box methodology
└── SITEMAP.md                # route & service map
```

---

## ☁️ Deploy to the cloud

Infrastructure-as-code to stand up the whole stack — the vulnerable app **and** the
CTFd platform — on AWS, behind login, for solo or team (max 3) play, lives in
[`deploy/`](deploy/). See [`deploy/README.md`](deploy/README.md).
