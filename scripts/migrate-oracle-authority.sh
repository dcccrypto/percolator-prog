#!/usr/bin/env bash
# migrate-oracle-authority.sh — PERC-8130
#
# Batch-updates oracle_authority on every deployed slab to the current
# keeper key so the cranker can resume pushing prices.
#
# Usage:
#   KEEPER_PUBKEY=2JaSzRY... ./scripts/migrate-oracle-authority.sh
#
# Requirements:
#   - UPGRADE_AUTH keypair must be the slab admin (FF7KFfU5...)
#   - solana CLI configured for devnet
#   - percolator-keeper CLI (packages/keeper/bin/set-oracle-authority.ts) OR
#     the raw percolator-prog instruction encoded here
#
# The program already has SetOracleAuthority (tag=16) at every tier.
# This script calls it for each known slab.
#
# ⚠️  DO NOT run on mainnet without Khubair approval.
# ⚠️  After running, restart the keeper to verify cranking resumes.

set -euo pipefail

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# ── Config ──────────────────────────────────────────────────────────────────
UPGRADE_AUTH="$HOME/.config/solana/percolator-upgrade-authority.json"
RPC="${RPC:-https://api.devnet.solana.com}"

# Current keeper key — set via env or hardcode here
KEEPER_PUBKEY="${KEEPER_PUBKEY:-2JaSzRY6qYFGiV9P7iHkHiXvB3kxZqvx6b2cHbW5Vmde}"

# Program IDs
SMALL_PROG="FwfBKZXbYr4vTK23bMFkbgKq3npJ3MSDxEaKmq9Aj4Qn"
MEDIUM_PROG="g9msRSV3sJmmE3r5Twn9HuBsxzuuRGTjKCVTKudm9in"
LARGE_PROG="FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD"

# ── Known slab addresses ─────────────────────────────────────────────────────
# Add/remove as markets are created. Source: indexer /api/markets or GH#1748.
# Format: "SLAB_PUBKEY PROGRAM_ID MARKET_NAME"
SLABS=(
    # BTC/USD (GH#1754 — completely non-tradeable)
    # SEEKER/SKR (GH#1748)
    # Other markets (add addresses from indexer)
    # TODO: populate from `percolator-indexer markets list --rpc $RPC`
)

log() { echo "[$(date -u '+%H:%M:%S')] $*"; }

# ── Dependency check ─────────────────────────────────────────────────────────
if ! command -v solana &>/dev/null; then
    echo "ERROR: solana CLI not found. Install from https://solana.com/docs/intro/installation"
    exit 1
fi

if [[ ! -f "$UPGRADE_AUTH" ]]; then
    echo "ERROR: Upgrade authority keypair not found at $UPGRADE_AUTH"
    exit 1
fi

ADMIN_PUBKEY=$(solana-keygen pubkey "$UPGRADE_AUTH")
log "Admin (slab admin):  $ADMIN_PUBKEY"
log "New keeper/oracle:   $KEEPER_PUBKEY"
log "RPC:                 $RPC"
log ""

# ── Build instruction data (SetOracleAuthority = tag 16 + 32 bytes pubkey) ──
# We use the solana CLI `--data` hex option via a small inline script.
# tag=16 (0x10) followed by the 32 raw bytes of KEEPER_PUBKEY.
build_ix_data() {
    local pubkey="$1"
    node - <<EOF
const { PublicKey } = require('@solana/web3.js');
const pk = new PublicKey('$pubkey');
const bytes = pk.toBytes();
const buf = Buffer.alloc(33);
buf[0] = 16; // TAG_SET_ORACLE_AUTHORITY
bytes.copy(buf, 1);
process.stdout.write(buf.toString('hex'));
EOF
}

# ── Auto-discover slabs from percolator-indexer (if installed) ───────────────
discover_slabs() {
    log "Attempting auto-discovery via percolator-indexer..."
    if command -v percolator-indexer &>/dev/null; then
        percolator-indexer markets list --rpc "$RPC" --format json 2>/dev/null \
            | node -e "
const d = require('fs').readFileSync('/dev/stdin','utf8');
const markets = JSON.parse(d);
markets.forEach(m => console.log(m.slab_pubkey + ' ' + m.program_id + ' ' + m.symbol));
" 2>/dev/null || true
    else
        log "percolator-indexer not found — using SLABS array above"
    fi
}

# ── Main loop ────────────────────────────────────────────────────────────────
log "=== PERC-8130: SetOracleAuthority migration ==="
log ""

# Try auto-discover first
DISCOVERED=$(discover_slabs) || true
if [[ -n "$DISCOVERED" ]]; then
    log "Auto-discovered markets:"
    echo "$DISCOVERED"
    readarray -t SLABS_DYNAMIC <<< "$DISCOVERED"
else
    SLABS_DYNAMIC=()
fi

# Merge hardcoded + discovered (deduplicate by first field)
ALL_SLABS=("${SLABS[@]}" "${SLABS_DYNAMIC[@]}")

if [[ ${#ALL_SLABS[@]} -eq 0 ]]; then
    log "ERROR: No slabs found. Either:"
    log "  1. Populate the SLABS array in this script, or"
    log "  2. Install percolator-indexer and ensure it can reach $RPC"
    exit 1
fi

PASS=0
FAIL=0

for entry in "${ALL_SLABS[@]}"; do
    SLAB_PUBKEY=$(echo "$entry" | awk '{print $1}')
    PROG_ID=$(echo "$entry" | awk '{print $2}')
    MARKET=$(echo "$entry" | awk '{print $3}')

    [[ -z "$SLAB_PUBKEY" ]] && continue

    log "Processing $MARKET ($SLAB_PUBKEY) on program $PROG_ID..."

    IX_DATA=$(build_ix_data "$KEEPER_PUBKEY" 2>/dev/null) || {
        log "  ERROR: Failed to build instruction data (node + @solana/web3.js required)"
        FAIL=$((FAIL + 1))
        continue
    }

    # Send the transaction
    if solana program invoke "$PROG_ID" \
        --keypair "$UPGRADE_AUTH" \
        --url "$RPC" \
        --with-signer "$UPGRADE_AUTH" \
        --account "$SLAB_PUBKEY" \
        --data "$IX_DATA" 2>&1; then
        log "  ✅ $MARKET oracle authority updated to $KEEPER_PUBKEY"
        PASS=$((PASS + 1))
    else
        log "  ❌ $MARKET FAILED"
        FAIL=$((FAIL + 1))
    fi
done

log ""
log "=== Migration complete: $PASS passed, $FAIL failed ==="

if [[ $FAIL -gt 0 ]]; then
    log "WARNING: $FAIL markets still have mismatched oracle authority."
    log "Re-run this script or manually call SetOracleAuthority (tag=16) for each failed slab."
    exit 1
fi

log ""
log "Next steps:"
log "  1. Restart keeper service on Railway"
log "  2. Verify crank resumes: check keeper logs for PushOraclePrice confirmations"
log "  3. Confirm BTC and SEEKER markets show fresh oracle timestamps on-chain"
