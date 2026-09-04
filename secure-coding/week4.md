# Secure coding — Week 4 (detection phase)

Week 4 has no classic fix. Instead, the player proposes what logging and alerting
would have caught the attack earlier (maps to A09 Logging & Alerting Failures).

- **W4-01** — Find the entry point (log analysis)
- **W4-02** — Reconstruct the scope of the leak
- **W4-03** — Timeline of lateral movement
- **W4-04** — Static analysis of the (benign) sample
- **W4-05** — Malware analysis report (human-graded, outside the app)

Reference answer: what the app did not log but should have (missing audit logs on
role changes, on access to foreign objects, on repeated login failures; no alert
on an anomalous request count / UNION patterns in parameters).

> Note: Week 4 (the artifact generator) is not built yet — this is the planned
> outline for the detection phase.
