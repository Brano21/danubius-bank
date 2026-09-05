# Week 4 — evidence generator (blue-team)

Week 4 is **investigation, not exploitation**. There are no new vulnerable routes.
This module renders one coherent incident — the same attacker who abused the
Week-1/2 flaws — into offline artifacts that you hand to players through CTFd.

## Artifacts (the bundle)

| file | format | used by |
|---|---|---|
| `access.log` | combined HTTP access log | W4-01 (spot the attack), context for all |
| `auth.log` | auth events (syslog-ish) | **W4-01** flag |
| `capture.pcap` | real libpcap, open in Wireshark | **W4-02**, **W4-03**, **W4-05** flags |
| `Danubius-StatementViewer-setup.exe` | benign Windows PE32 | **W4-04** flag |
| `README-for-players.txt` | incident brief + tasks | players |
| `sha256sums.txt` | integrity | operator |

> The `.exe` is a **benign training artifact**: its entry point is `xor eax,eax;
> ret` and it declares (but never calls) the "malicious" APIs. It performs no
> network, file or registry action. Distribute and analyse it safely.

## Tasks & flags

All five are auto-graded (a `RPC{...}` flag). Values come from the environment
(`FLAG_W4_01` … `FLAG_W4_05`); demo defaults are used if unset.

| task | skill | flag lives in |
|---|---|---|
| W4-01 | log triage — find the credential bypass | `auth.log` (`token=`) |
| W4-02 | breach scope — the PAN data leak | `capture.pcap` (UNION response audit ref) |
| W4-03 | lateral movement — BOLA into the API | `capture.pcap` (VIP `accounts/3` response) |
| W4-04 | static analysis — deobfuscate the sample | the `.exe` (`cfg=` base64 + single-byte XOR) |
| W4-05 | C2 reconstruction — reassemble the beacon | `capture.pcap` (`/beacon?d=` base64 chunks) |

## Generate the bundle

Inside the running stack (Flask present, works at any `WEEK`):

```bash
docker compose exec web python -m app.modules.week4_evidence.generate --out /tmp/w4
docker compose cp web:/tmp/w4 ./week4_out          # copy the files out
```

Or standalone from this folder (standard library only, no Flask/DB needed):

```bash
cd app/modules/week4_evidence && python generate.py --out out
```

Either way the tool prints the flag → location mapping so you can configure CTFd.

## Operator download page (optional)

With `WEEK=4` the app also serves an operator-only page:

```
/evidence?key=<WEEK4_KEY>        # WEEK4_KEY defaults to GATE_ADMIN_PASSWORD
```

It links `danubius_week4_evidence.zip` and shows the flag mapping. A wrong/absent
key returns 404. **Do not give players this key** — the bundle embeds every flag.

## Verify

```bash
python tests/test_week4.py        # generates a bundle and confirms all 5 flags are recoverable
```
