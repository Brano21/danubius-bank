# ☁️ Deploy the Danubius Bank CTF

The **whole stack** is one `docker-compose.yml`, brought up (and CTFd seeded) by
one script — `deploy/manual-setup.sh`. Two ways to run it on a server:

- **[Manual EC2](#option-a--manual-ec2-recommended)** — you click the instance in
  the AWS console; the script does the software. *Recommended if Terraform feels
  like overkill.*
- **[Terraform](#option-b--terraform)** — cloud-init runs the exact same script.

```
                 allowed IPs only
   players ───────────────────────────►  ┌──────────── EC2 (Ubuntu) ───────────┐
     :80   CTFd  (sign in, read, submit)  │  ONE docker compose stack:          │
     :8080 App gate (attack the target)   │  gate + web + db + ollama +         │
                                          │  exporter + CTFd (+ its db/redis)   │
                                          └─────────────────────────────────────┘
```

## One account per player (how login works)

There is **no separate player list**. **CTFd is the single source of truth:**

1. You (admin) create each player in **CTFd → Admin → Users** (self-registration
   is off). Give them a username + password.
2. The player uses **those same credentials** at the CTFd scoreboard **and** at the
   app gate on `:8080` — the gate validates every login against CTFd.
3. Inside the bank they either register (`/register`) or use the W1-01 bypass.

The **admin** account is one credential too: `CTFD_ADMIN_*` in `.env` is the CTFd
admin (creates users, runs the scoreboard) **and** the gate operator (monitoring at
`:8080/_gate/admin`). Keep `GATE_ADMIN_*` equal to `CTFD_ADMIN_*`.

---

## Run it locally first (no AWS)

```bash
cp .env.example .env                 # set CTFD_ADMIN_PASSWORD (== GATE_ADMIN_PASSWORD)
docker compose up -d --build         # gate :8080 + CTFd :80, one stack
python -m pip install requests
set -a; . ./.env; set +a
CTFD_URL=http://localhost APP_TARGET_URL=http://localhost:8080 python deploy/ctfd/seed_ctfd.py
```

Open CTFd at `http://localhost/`, sign in as the admin, create a test player under
**Admin → Users**, then sign in at the app gate `http://localhost:8080/` with that
player's credentials.

---

## Sizing (pick before you launch)

| WEEK | What runs | Instance | Disk |
|:----:|-----------|----------|------|
| 4 (default) | Full lab incl. the Week-3 LLM (Ollama 3B) | **m5.2xlarge** (32 GB RAM) | 60 GB |
| 3 | + LLM, no Week-4 forensics | m5.xlarge / m5.2xlarge (≥16 GB) | 40 GB |
| 1–2 | Web + API only, **no LLM** | m5.large / t3.large (8 GB) | 30 GB |

The LLM is the RAM hog and the ~2 GB first-boot download. For a cheap web/API run,
set `WEEK=2` and use a small instance.

---

## Option A — Manual EC2 (recommended)

**1. Launch the instance (AWS console):**
- **AMI:** Ubuntu Server 22.04 LTS (or 24.04).
- **Type / disk:** per the sizing table above (default: `m5.2xlarge`, 60 GB gp3).
- **Key pair:** create/pick one so you can SSH.
- **Security group — inbound (scope the source to your/players' IPs, never
  `0.0.0.0/0`):**

  | Port | Purpose | Source |
  |:----:|---------|--------|
  | 22 | SSH | **your** IP /32 |
  | 80 | CTFd scoreboard | players' IPs |
  | 8080 | App gate (target) | players' IPs |

**2. Install Docker + bring the stack up (one command):**
```bash
ssh ubuntu@<PUBLIC_IP>
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/Brano21/danubius-bank.git
cd danubius-bank
sudo ADMIN_PASSWORD='pick-a-strong-admin-password' bash deploy/manual-setup.sh
```
`manual-setup.sh` installs Docker if missing, writes `.env` (random secrets + a
random flag per task), runs `docker compose up -d --build`, and seeds CTFd. **First
boot ~5–15 min** (image builds + the LLM model). Re-running it is safe (reuses
`.env`, won't double-seed). When it finishes it prints the URLs and the admin login.

Optional overrides: `WEEK=2`, `ADMIN_USER=...`, `CTF_NAME='...'`, `MAX_TEAM_SIZE=3`.

**3. Create players:** open `http://<PUBLIC_IP>/`, sign in as admin, **Admin →
Users → +** (or CSV import). Hand each player their username/password — that is
also their app-gate login.

---

## Option B — Terraform

Cloud-init runs `deploy/manual-setup.sh` for you.

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # edit it
terraform init
terraform apply
```

Set at least:

| Variable | Why |
|----------|-----|
| `allowed_cidr` | Who can reach the lab, e.g. `x.x.x.x/32`. Never `0.0.0.0/0`. |
| `ctfd_admin_password` | The one admin password (CTFd admin + gate operator). |
| `ssh_key_name` *(optional)* | An existing EC2 key pair, if you want SSH. |
| `instance_type` / `week` *(optional)* | See the sizing table. |

`terraform apply` prints `ctfd_url` and `app_gate_url`. Watch progress:
`ssh ubuntu@<ip>` then `tail -f /var/log/danubius-deploy.log`. Tear down with
`terraform destroy`.

> ⚠️ `allowed_cidr` is a single CIDR. To let a whole class in from different IPs,
> widen it (e.g. an office `/24`) or, for a real event, put an ALB in front. The
> current SG opens 80/8080 to exactly this one range.

---

## Everyday operations

**Add / remove a player:** CTFd → Admin → Users. Nothing to restart — the gate
picks it up on the player's next login (it asks CTFd every time).

**See who's attacking the target:** the gate monitoring dashboard at
`http://<ip>:8080/_gate/admin` (admin login) logs every proxied request with the
player's real CTFd identity.

**Reset only the vulnerable app** (keep CTFd scores/players):
```bash
cd /opt/danubius-bank   # or wherever you cloned it
docker compose rm -sfv db web && docker compose up -d
```

**Re-seed CTFd by hand** (only if the automatic seed failed — it won't re-run once
`.ctfd_seeded` exists; delete that file to force it):
```bash
set -a; . ./.env; set +a
CTFD_URL=http://localhost APP_TARGET_URL=http://<ip>:8080 python3 deploy/ctfd/seed_ctfd.py
```

**Team size** is best-effort via the API; if it didn't stick, set it in CTFd
**Admin → Config → Teams**.

**After a reboot** the whole stack comes back on its own (`restart: unless-stopped`).

---

## Notes / troubleshooting

- **HTTPS:** this lab is HTTP-only. For a real event put an ALB/CloudFront or a
  reverse proxy with a certificate in front, and set `GATE_COOKIE_SECURE=1` in `.env`.
- **CTFd version** is pinned in the root `docker-compose.yml` (`ctfd/ctfd:3.7.5`).
- **`.env` has no defaults for the required secrets** (`SECRET_KEY`, `GATE_SECRET`,
  `GATE_ADMIN_PASSWORD`, `CTFD_SECRET_KEY`): `docker compose up` fails fast if it's
  missing. The setup script generates them for you.
- This is a **deliberately vulnerable** lab. Keep the security group tight, use a
  throwaway/isolated AWS account, and destroy it after the event.
