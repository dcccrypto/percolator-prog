#!/usr/bin/env bash
#
# compare-trade-cu.sh — Automated before/after trade CU benchmark for PERC-154
#
# Usage: ./scripts/compare-trade-cu.sh
#
# This script:
# 1. Builds the program at the pre-optimization commit (75bab65)
# 2. Runs the trade CU benchmark → saves to before.txt
# 3. Builds the program at HEAD (post-optimization)
# 4. Runs the trade CU benchmark → saves to after.txt
# 5. Prints a side-by-side comparison
#
# Requirements: Rust toolchain, solana-cli (for cargo build-sbf), litesvm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$REPO_DIR/benchmark-results"

mkdir -p "$RESULTS_DIR"

BEFORE_COMMIT="75bab65"  # Last commit before PERC-154 optimization
AFTER_COMMIT="HEAD"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     PERC-154 Trade CU Comparison Benchmark              ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║ Before: $BEFORE_COMMIT (pre-optimization)                       ║"
echo "║ After:  $AFTER_COMMIT (post-optimization)                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

cd "$REPO_DIR"

# Stash any local changes
STASH_MSG="compare-trade-cu-$(date +%s)"
git stash push -m "$STASH_MSG" 2>/dev/null || true

cleanup() {
    echo
    echo "Restoring original state..."
    git checkout - 2>/dev/null || true
    git stash pop 2>/dev/null || true
}
trap cleanup EXIT

# ── BEFORE (pre-optimization) ──────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1/4: Building BEFORE ($BEFORE_COMMIT)..."
git checkout "$BEFORE_COMMIT" 2>/dev/null

echo "  Building BPF (--features test)..."
cargo build-sbf --features test 2>&1 | tail -3

echo "Step 2/4: Running trade CU benchmark (BEFORE)..."
cargo test --release --test trade_cu_benchmark benchmark_trade_cu_summary_table -- --nocapture 2>&1 \
    | tee "$RESULTS_DIR/before.txt"

# ── AFTER (post-optimization) ──────────────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3/4: Building AFTER (master/HEAD)..."
git checkout - 2>/dev/null

echo "  Building BPF (--features test)..."
cargo build-sbf --features test 2>&1 | tail -3

echo "Step 4/4: Running trade CU benchmark (AFTER)..."
cargo test --release --test trade_cu_benchmark benchmark_trade_cu_summary_table -- --nocapture 2>&1 \
    | tee "$RESULTS_DIR/after.txt"

# ── COMPARISON ─────────────────────────────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Comparison"
echo

# Extract CU values from both files
extract_cu() {
    local file="$1"
    grep "│" "$file" | grep -v "Operation" | grep -v "──" | while IFS='│' read -r _ op cu _; do
        op=$(echo "$op" | xargs)
        cu=$(echo "$cu" | xargs)
        if [ -n "$op" ] && [ -n "$cu" ]; then
            printf "%-35s %s\n" "$op" "$cu"
        fi
    done
}

echo "┌────────────────────────────────┬──────────┬──────────┬─────────┐"
echo "│ Operation                      │  BEFORE  │  AFTER   │ Savings │"
echo "├────────────────────────────────┼──────────┼──────────┼─────────┤"

# Parse CU from both files
paste <(grep "│" "$RESULTS_DIR/before.txt" | grep -E "[0-9]" | grep -v "Operation") \
      <(grep "│" "$RESULTS_DIR/after.txt" | grep -E "[0-9]" | grep -v "Operation") | \
while IFS=$'\t' read -r before_line after_line; do
    # Extract operation name and CU from before line
    op=$(echo "$before_line" | awk -F'│' '{print $2}' | xargs)
    before_cu=$(echo "$before_line" | awk -F'│' '{print $3}' | xargs)
    after_cu=$(echo "$after_line" | awk -F'│' '{print $3}' | xargs)

    if [ -n "$before_cu" ] && [ -n "$after_cu" ]; then
        savings=$((before_cu - after_cu))
        if [ "$before_cu" -gt 0 ]; then
            pct=$(echo "scale=1; $savings * 100 / $before_cu" | bc 2>/dev/null || echo "?")
            printf "│ %-30s │ %8s │ %8s │ %+6d  │\n" "$op" "$before_cu" "$after_cu" "$savings"
        fi
    fi
done 2>/dev/null || echo "  (Manual comparison needed — see $RESULTS_DIR/before.txt and $RESULTS_DIR/after.txt)"

echo "└────────────────────────────────┴──────────┴──────────┴─────────┘"
echo
echo "Full results saved to:"
echo "  Before: $RESULTS_DIR/before.txt"
echo "  After:  $RESULTS_DIR/after.txt"
echo
echo "Done! Share these results with QA for PERC-156."
