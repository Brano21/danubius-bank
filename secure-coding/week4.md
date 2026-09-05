# Secure coding — Week 4 (detection & response)

Week 4 has no code patch. Instead of fixing a line, the learner reads the evidence
the attacker left behind and answers: **what should the bank have logged, detected
or blocked so this incident was caught in minutes, not reconstructed after the
fact?** This maps to **OWASP A09 — Security Logging & Monitoring Failures**.

The five tasks (all auto-graded from the offline bundle — see
`app/modules/week4_evidence/`) each anchor one detection lesson.

| task | what happened | the detection that was missing |
|---|---|---|
| **W4-01** | credential-bypass login (SQLi) succeeded | alert on **auth anomalies**: N failures then a success from one IP, a login with no matching credential, a SQL error on `/login` |
| **W4-02** | 5 PANs dumped via a UNION in a search box | alert on **query anomalies** (SQL errors, `UNION SELECT`/`--` in parameters) and on a response returning **card-number-shaped data** / an oversized result |
| **W4-03** | BOLA id-walk `accounts/1→2→3` | log **object-level access**; alert when one identity reads many **foreign** object ids in sequence |
| **W4-04** | a sample with C2/persistence IOCs on a host | **EDR / static scanning** on downloads; flag known-bad imports, mutexes, autorun registry writes |
| **W4-05** | data beaconed out to an unknown domain | **egress monitoring / DNS logging**; alert on traffic to a newly-seen external domain and on regular chunked `GET` beacons |

## Reference answer — controls the app/stack lacked

**Logging (what to record).**
- Authentication: every success **and** failure with `user`, source IP, and the
  reason; explicitly record when a request produced a SQL error.
- Authorization: log object access as `actor → object_id → decision`, so
  cross-tenant reads are visible after the fact.
- Admin/sensitive actions: role changes, card unblock, large transfers — with the
  actor. (These are the W2 flaws; here they become the audit trail.)
- Keep logs **structured** (JSON) and shipped off-box so an attacker on the host
  can't trim them.

**Detection (what to alert on).**
- Brute/anomaly: ≥ K failed logins in a window from one IP, or *fail→success*.
- Injection signatures: `UNION SELECT`, `OR '1'='1`, `-- `, `;` in query params;
  any DB syntax error reaching the app.
- Access-control anomaly: one token reading many distinct/foreign object ids, or
  hitting `/admin/*` without an admin role.
- Data-loss: responses matching PAN/IBAN patterns; unusually large exports.
- Egress/C2: connections to never-before-seen domains; periodic fixed-size beacons.

**Response.** Rate-limit and step-up auth on the login anomaly; auto-disable the
session/token that walked foreign objects; block the C2 domain and pull the host;
rotate the exposed card data and notify. A short **incident timeline** (entry →
leak → lateral movement → exfil) built from the three artifacts is the deliverable
the learner can reason about — and it lines up 1:1 with W4-01…W4-05.

> This is the blue-team mirror of Weeks 1–3: the same SQLi, BOLA and weak-auth
> flaws, now seen from the defender's logs instead of the attacker's payloads.
