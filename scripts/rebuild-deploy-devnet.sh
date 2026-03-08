#!/usr/bin/env bash
# rebuild-deploy-devnet.sh — PERC-383
# Rebuild all 3 tier programs from main (314391b) and redeploy to devnet
set -euo pipefail

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

REPO="$HOME/percolator-prog"
UPGRADE_AUTH="$HOME/.config/solana/percolator-upgrade-authority.json"
RPC="https://api.devnet.solana.com"

SMALL_ID="FwfBKZXbYr4vTK23bMFkbgKq3npJ3MSDxEaKmq9Aj4Qn"
MEDIUM_ID="g9msRSV3sJmmE3r5Twn9HuBsxzuuRGTjKCVTKudm9in"
LARGE_ID="FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD"

log() { echo "[$(date -u '+%H:%M:%S')] $*"; }

cd "$REPO"
log "At commit: $(git log --oneline -1)"
log "Deployer balance: $(solana balance $UPGRADE_AUTH --url $RPC)"

# ── SMALL (256 slots) ───────────────────────────────────────────
log "=== Building SMALL tier (features: small,devnet) ==="
cargo build-sbf --features small,devnet 2>&1
cp target/deploy/percolator_prog.so target/deploy/percolator_prog_small.so
cp target/deploy/percolator_prog.so deploy-artifacts/percolator_prog_small.so
log "=== Deploying SMALL → $SMALL_ID ==="
solana program deploy \
  --program-id "$SMALL_ID" \
  --upgrade-authority "$UPGRADE_AUTH" \
  --url "$RPC" \
  target/deploy/percolator_prog_small.so
log "SMALL deployed ✅"

# ── MEDIUM (1024 slots) ─────────────────────────────────────────
log "=== Building MEDIUM tier (features: medium,devnet) ==="
cargo build-sbf --features medium,devnet 2>&1
cp target/deploy/percolator_prog.so target/deploy/percolator_prog_medium.so
cp target/deploy/percolator_prog.so deploy-artifacts/percolator_prog_medium.so
log "=== Deploying MEDIUM → $MEDIUM_ID ==="
solana program deploy \
  --program-id "$MEDIUM_ID" \
  --upgrade-authority "$UPGRADE_AUTH" \
  --url "$RPC" \
  target/deploy/percolator_prog_medium.so
log "MEDIUM deployed ✅"

# ── LARGE (4096 slots, default/no size feature) ─────────────────
log "=== Building LARGE tier (features: devnet only) ==="
cargo build-sbf --features devnet 2>&1
cp target/deploy/percolator_prog.so target/deploy/percolator_prog_large.so
log "=== Deploying LARGE → $LARGE_ID ==="
solana program deploy \
  --program-id "$LARGE_ID" \
  --upgrade-authority "$UPGRADE_AUTH" \
  --url "$RPC" \
  target/deploy/percolator_prog_large.so
log "LARGE deployed ✅"

log "=== All 3 tiers rebuilt and deployed from 314391b ==="
log "Deployer balance after: $(solana balance $UPGRADE_AUTH --url $RPC)"
