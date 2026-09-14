#!/usr/bin/env bash
# =============================================================================
# Danubius Bank CTF - one-command setup for a MANUALLY created server.
#
# You create the EC2 (or any Ubuntu box) and open ports 22/80/8080 yourself,
# clone this repo, then run this from the repo root:
#
#     sudo ADMIN_PASSWORD='your-strong-admin-password' bash deploy/manual-setup.sh
#
# It installs Docker if missing, writes .env with random secrets + a random flag
# per task, brings up the WHOLE stack (vulnerable app on :8080 + CTFd on :80),
# and seeds CTFd (team mode, admin-only registration, all 19 challenges with the
# matching flags). Re-running it is safe: it reuses an existing .env and does not
# re-seed CTFd once it has been seeded.
#
# Inputs (env vars):
#   ADMIN_PASSWORD   REQUIRED - the single admin password (CTFd admin + gate operator).
#   ADMIN_USER       optional - admin username (default: ctfadmin).
#   WEEK             optional - 1..4 (default: 4 = full lab).
#   CTF_NAME         optional - scoreboard title (default: "Danubius Bank CTF").
#   MAX_TEAM_SIZE    optional - max players per team (default: 3).
#   PUBLIC_IP        optional - overrides auto-detection (used in challenge text).
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

ADMIN_USER="${ADMIN_USER:-ctfadmin}"
WEEK="${WEEK:-4}"
CTF_NAME="${CTF_NAME:-Danubius Bank CTF}"
MAX_TEAM_SIZE="${MAX_TEAM_SIZE:-3}"

log() { echo "== $* =="; }

# --- 0) admin password is required (honours 'no silent default') -------------
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  if [ -t 0 ]; then
    read -r -s -p "Admin password (CTFd admin + gate operator): " ADMIN_PASSWORD; echo
  fi
fi
if [ -z "${ADMIN_PASSWORD:-}" ]; then
  echo "ERROR: ADMIN_PASSWORD is required. Re-run with:" >&2
  echo "  sudo ADMIN_PASSWORD='...' bash deploy/manual-setup.sh" >&2
  exit 1
fi

# --- 1) Docker + compose plugin ----------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker"
  curl -fsSL https://get.docker.com | sh
  usermod -aG docker "${SUDO_USER:-ubuntu}" 2>/dev/null || true
  systemctl enable --now docker || true
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: 'docker compose' plugin not available. Install docker-compose-plugin." >&2
  exit 1
fi

# --- 2) python3 + requests (for the CTFd seeder) -----------------------------
command -v python3 >/dev/null 2>&1 || { apt-get update -y && apt-get install -y python3; }
python3 -c 'import requests' 2>/dev/null || pip3 install --quiet requests 2>/dev/null \
  || { apt-get update -y && apt-get install -y python3-requests; }

# --- 3) public IP (only used to print the URL in challenge text) -------------
PUBLIC_IP="${PUBLIC_IP:-$(curl -fsS --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null \
  || curl -fsS --max-time 3 https://checkip.amazonaws.com 2>/dev/null \
  || echo localhost)}"

# --- 4) .env with random secrets + a random flag per task (once) -------------
if [ ! -f .env ]; then
  log "generating .env (random secrets + flags)"
  rand() { openssl rand -hex "${1:-16}"; }
  {
    echo "WEEK=$WEEK"
    echo "SECRET_KEY=$(rand 16)"
    echo "DB_NAME=danubius"
    echo "DB_USER=danubius"
    echo "DB_PASSWORD=$(rand 16)"
    echo "OLLAMA_MODEL=llama3.2:3b"
    echo "CTFD_ADMIN_USER=$ADMIN_USER"
    echo "CTFD_ADMIN_PASSWORD=$ADMIN_PASSWORD"
    echo "GATE_ADMIN_USER=$ADMIN_USER"
    echo "GATE_ADMIN_PASSWORD=$ADMIN_PASSWORD"
    echo "CTF_NAME=$CTF_NAME"
    echo "MAX_TEAM_SIZE=$MAX_TEAM_SIZE"
    echo "CTFD_SECRET_KEY=$(rand 16)"
    echo "CTFD_DB_ROOT_PASSWORD=$(rand 12)"
    echo "GATE_SECRET=$(rand 16)"
    echo "CTFD_URL=http://ctfd:8000"
    echo "GATE_COOKIE_SECURE=0"
    echo "WEEK4_KEY=$ADMIN_PASSWORD"
    for id in W1_01 W1_02 W1_03 W1_04 W1_05 \
              W2_01 W2_02 W2_03 W2_04 W2_05 \
              W3_01 W3_02 W3_03 W3_04 \
              W4_01 W4_02 W4_03 W4_04 W4_05; do
      echo "FLAG_$id=RPC{$(rand 8)}"
    done
  } > .env
  chmod 600 .env
else
  log ".env already present - reusing it"
fi

# --- 5) bring up the whole stack ---------------------------------------------
log "docker compose up (build images, pull the ~2GB LLM model on first run)"
docker compose up -d --build

# --- 6) wait for CTFd, then seed once ----------------------------------------
log "waiting for CTFd on :80"
for _ in $(seq 1 60); do
  curl -fsS http://localhost:80/ >/dev/null 2>&1 && break || sleep 5
done

if [ -f .ctfd_seeded ]; then
  log "CTFd already seeded (.ctfd_seeded present) - skipping seed"
else
  log "seeding CTFd (team mode, admin-only registration, 19 challenges)"
  set -a; . ./.env; set +a
  if CTFD_URL="http://localhost:80" \
     APP_TARGET_URL="http://$PUBLIC_IP:8080" \
     python3 deploy/ctfd/seed_ctfd.py; then
    touch .ctfd_seeded
  else
    echo "WARN: CTFd seeding failed - see output above. Fix and re-run this script." >&2
  fi
fi

echo
log "DONE"
echo "  CTFd scoreboard : http://$PUBLIC_IP/         (admin: $ADMIN_USER)"
echo "  App gate        : http://$PUBLIC_IP:8080/    (players sign in with their CTFd login)"
echo "  Gate monitoring : http://$PUBLIC_IP:8080/_gate/admin   (admin: $ADMIN_USER)"
echo
echo "  Next: open CTFd -> Admin -> Users, create player accounts. Those same"
echo "        credentials let each player through the app gate."
