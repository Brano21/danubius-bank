# ☁️ Deploy the Danubius Bank CTF to AWS

Infrastructure-as-code that stands up the **whole stack** on one EC2 instance:

- the **vulnerable Danubius Bank app** (behind its gate) — the target, on `:8080`;
- the **CTFd** platform — where players sign in and submit flags, on `:80`;
- fresh **random flags** generated at boot and wired into *both* (so CTFd matches
  the app), plus all 19 challenges seeded with descriptions, hints and points.

Play is **solo or team** (CTFd team mode, max size configurable — default 3). The
whole thing is **network-scoped to your IP** (`allowed_cidr`); players still log in
at CTFd and at the app gate on top of that.

```
                 allowed_cidr only
   players ───────────────────────────►  ┌─────────── EC2 (Ubuntu) ───────────┐
     :80   CTFd  (sign in, read, submit)  │  docker compose (CTFd + db + redis)│
     :8080 App gate (attack the target)   │  docker compose (gate+web+db+       │
                                          │                  ollama+exporter)  │
                                          └────────────────────────────────────┘
```

## Run it locally first (no AWS)

You can run the exact same two stacks on your own machine to try it end-to-end:

```bash
# 1) the vulnerable app (from the repo root)
cp .env.example .env
WEEK=4 docker compose up -d --build                        # gate → http://localhost:8080

# 2) CTFd
docker compose -f deploy/ctfd/docker-compose.yml up -d     # CTFd → http://localhost:80

# 3) set up CTFd (team mode) + seed all 19 challenges with matching flags
pip install requests
set -a; . .env; set +a                                     # load the FLAG_* values
CTFD_URL=http://localhost CTF_NAME="Danubius Bank CTF" \
CTFD_ADMIN_USER=ctfadmin CTFD_ADMIN_PASSWORD='change-me' \
APP_TARGET_URL=http://localhost:8080 MAX_TEAM_SIZE=3 \
python3 deploy/ctfd/seed_ctfd.py
```

Open CTFd at `http://localhost/` (register + join a team), read a challenge, attack
the app at `http://localhost:8080/`, submit the flag. Tear down with
`docker compose down` in both places (add `-v` to wipe data).

---

## Prerequisites (AWS)

- **Terraform ≥ 1.3** and **AWS credentials** configured (`aws configure`, or env
  vars / SSO). The identity needs EC2 + VPC permissions.
- The repo must be reachable by the instance at boot (`repo_url`): public, or embed
  a token. Default is `github.com/Brano21/danubius-bank`.

## Deploy

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # then edit it (see below)
terraform init
terraform apply
```

Set at least these in `terraform.tfvars`:

| Variable | Why |
|----------|-----|
| `allowed_cidr` | **Your** IP as `x.x.x.x/32` — who can reach the lab. Never `0.0.0.0/0`. |
| `ctfd_admin_password` | CTFd admin password. |
| `ssh_key_name` *(optional)* | An existing EC2 key pair, if you want SSH. |
| `instance_type` *(optional)* | `m5.2xlarge` (32 GB) for the full lab incl. the LLM; `m5.large` + `week=2` for a cheap web/API-only lab. |
| `week` *(optional)* | `1`–`4`. `4` = everything. |

`terraform apply` prints the URLs:

```
ctfd_url     = http://<ip>/
app_gate_url = http://<ip>:8080/
```

**First boot takes ~5–15 min** (build images, pull the ~2 GB LLM model, set up and
seed CTFd). Watch it: `ssh ubuntu@<ip>` then `tail -f /var/log/danubius-deploy.log`.

## What happens on the box

`user_data.sh.tftpl` (cloud-init):

1. installs Docker + compose, clones the repo to `/opt/danubius-bank`;
2. writes `.env` with **random** gate/DB secrets and a **random flag per task**;
3. `docker compose up -d --build` — the vulnerable app (gate on `:8080`);
4. `docker compose -f deploy/ctfd/docker-compose.yml up -d` — CTFd on `:80`;
5. `deploy/ctfd/seed_ctfd.py` — runs the CTFd setup wizard in **team mode**, sets
   the max team size, and creates all 19 challenges (description + hints + the
   matching random flag), attaching the Week-4 evidence files.

## Players & teams — how they register and reach the target

There are **two logins**, by design:

**1. CTFd** (`http://<ip>/`) — the scoreboard. Players **self-register** (username +
email + password), then **create or join a team** (CTFd runs in *team mode*; a solo
player is just a team of one; max size = `max_team_size`, default **3**). Scoring is
per team. This is where they read challenges and submit flags. Week-4 challenges
have the evidence files attached — download and investigate.

**2. The target app gate** (`http://<ip>:8080/`) — the vulnerable bank sits behind a
thin access gate so only known players can touch it. Gate accounts are
**operator-managed** (there is *no* self-registration on the gate). Two ways to run
it for a CTF:

- **Shared credential (simplest, recommended).** The app is multi-tenant
  (Juice-Shop style — one instance, many players), so give *everyone* the same gate
  login. The repo ships `tester` / `test123` in `gate/players.json`; the seeded
  challenges already print it in their **Target** line, or announce it via a CTFd
  notification.
- **Per-team gate accounts.** Add one line per team to `gate/players.json`
  (`"team-name": "password"`) and `docker compose restart gate` on the host.

Once past the gate, players are on the real bank: they either **register a bank
account** (`/register`) or walk in with the **W1-01** login bypass — both work, the
flags are the same for everyone.

> **Player flow:** register on CTFd → join a team → open a challenge → it points at
> `http://<ip>:8080/` → sign in at the gate (shared credential) → solve → submit the
> flag back in CTFd.

## Cost & teardown

An `m5.2xlarge` is a few $/hour of runtime — **destroy it when you're done**:

```bash
terraform destroy
```

## Notes / troubleshooting

- **Re-seed by hand:** `ssh` in, `cd /opt/danubius-bank`, `set -a; . .env; set +a`,
  then `CTFD_URL=http://localhost CTF_NAME=... CTFD_ADMIN_USER=... CTFD_ADMIN_PASSWORD=... APP_TARGET_URL=http://<ip>:8080 python3 deploy/ctfd/seed_ctfd.py`.
- **Team size** is best-effort via the API; if it didn't stick, set it in CTFd
  **Admin → Config → Teams**.
- **HTTPS:** this lab is HTTP-only. For a real event put an ALB/CloudFront or a
  reverse proxy with a certificate in front, and set `GATE_COOKIE_SECURE=1`.
- **CTFd version** is pinned in `deploy/ctfd/docker-compose.yml`; bump it there if
  needed.
- This is a **deliberately vulnerable** lab. Keep `allowed_cidr` tight, use a
  throwaway/isolated AWS account, and destroy it after the event.
