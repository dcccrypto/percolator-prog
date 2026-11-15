#!/usr/bin/env bash
# Set up the sibling checkouts and reference programs the full wrapper suite needs, then run it through
# scripts/ci-test.sh with the same pins and env as the CI `build + test` job (allowlist verdict).
#
# Without the siblings, a local `cargo test --features devnet --no-fail-fast` reported 2,012 passed / 155 failed
# on rc23. 134 of those were environment only:
#   ../percolator-nft/target/deploy/percolator_nft.so        109 (v16_five_program_crosscut, v16_nft_e2e, v16_fee_split, ...)
#   ../percolator-stake/target/deploy/percolator_stake.so     16 (p4_wave_d, sec_v22d_adv, ...)
#   ../percolator-match-p2 / P2_MATCHER_SO                     8 (p1_fee_channel, p3_vault_lp)
#   GROWTH_BASE_SO (v2.1 wrapper 7c906e45)                     1 (growth_v19)
# The other 21 are tests/KNOWN_FAILING.txt and fail in CI too.
#
# Layout: the siblings go in the PARENT dir of this repo (the tests read ../<sibling>):
#   percolator percolator-nft percolator-stake percolator-match percolator-match-p2 percolator-match-v1
#   growth-base/{percolator-prog,percolator} test-so/
# Every checkout is pinned by ci/deployed-refs.env, the same refs ci.yml uses. A missing one is created as a
# detached worktree of a local clone in $PERC_GIT_MIRRORS/<repo> (default $HOME) when that clone has the pin,
# otherwise fetched by SHA from github.com/dcccrypto. An existing checkout at another commit, or with local
# changes, is a hard error; this script never moves or cleans it. Using a mirror runs `git worktree prune` and
# `worktree add` in that clone. If this repo itself sits in $HOME, $HOME/<sibling> IS the workspace sibling.
# env -i does not stop ~/.cargo/config.toml (target-dir, rustflags, rustc-wrapper); CI has none.
#
# Toolchain: everything is built with the deploy toolchain, cargo-build-sbf 3.1.14/3.1.15 (platform-tools v1.52),
# which must be first on PATH. CI builds the suite's programs with the agave v4.2.2 release instead (Linux). Its
# macOS build (cargo-build-sbf 4.1.0 / platform-tools v1.54) was measured here at 892 passed / 1,275 failed
# (InvalidAccountData at init) and it also unlinks the shared 1.89.0-sbpf-solana-v1.52 rustup toolchain, so it
# is deliberately not used.
#
# The suite runs under a clean environment (env -i + PATH/HOME/cargo vars + the CI values), so a stray
# *_SO / FUZZ_* / PERCOLATOR_ENGINE_UNPINNED export from an earlier experiment cannot change what is tested.
#
# Not covered: P1_FORK_DEPLOYED_SO / P1_FORK_MATCHER_SO (CI dumps them from devnet). Every test that reads
# them (p1_fork_regressions, p3_fork_regressions) is #[ignore]d on v2.2, so the counts do not change.
# scripts/ci-test.sh writes fixed /tmp/ci_*.txt files: do not run two suites at once on one machine.
#
# Usage: scripts/local-test-env.sh [--setup-only]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$ROOT/.." && pwd)"
MIRRORS="${PERC_GIT_MIRRORS:-$HOME}"
setup_only=0
case "${1:-}" in
  "") ;;
  --setup-only) setup_only=1 ;;
  *) echo "usage: $0 [--setup-only]"; exit 2 ;;
esac
set -a; . "$ROOT/ci/deployed-refs.env"; set +a

[ -z "${PERCOLATOR_ENGINE_UNPINNED:-}" ] || { echo "FATAL: PERCOLATOR_ENGINE_UNPINNED is set; this run must use the pinned engine"; exit 1; }

sbf_version() { cargo build-sbf --version 2>/dev/null | sed -n 1p; }
deploy_tc="$(sbf_version)"
echo "$deploy_tc" | grep -Eq "cargo-build-sbf (3\.1\.14|3\.1\.15)\b" \
  || { echo "FATAL: cargo-build-sbf 3.1.14/3.1.15 must be first on PATH, got: ${deploy_tc:-<none>}"; exit 1; }

checkout() { # path repo pin
  local dir="$WS/$1" repo="$2" pin="$3" have tmp
  if [ -e "$dir" ]; then
    have="$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)"
    [ "$have" = "$pin" ] || { echo "FATAL: $dir is at ${have:-<not a git checkout>}, pin is $pin. Move it aside and rerun."; exit 1; }
    [ -z "$(git -C "$dir" status --porcelain --untracked-files=all)" ] \
      || { echo "FATAL: $dir has local changes; the suite would test bytes that are not the pin"; git -C "$dir" status --short | head; exit 1; }
    echo "  ok      $1 @ ${pin:0:8}"
    return
  fi
  mkdir -p "$(dirname "$dir")"
  if git -C "$MIRRORS/$repo" cat-file -e "$pin^{commit}" 2>/dev/null; then
    git -C "$MIRRORS/$repo" worktree prune
    git -C "$MIRRORS/$repo" worktree add -q --detach "$dir" "$pin"
    echo "  added   $1 @ ${pin:0:8} (worktree of $MIRRORS/$repo)"
  else
    # Fetch the pin by SHA (as actions/checkout does) into a temp dir, then move it into place, so an
    # interrupted or failed fetch never leaves a checkout at the wrong commit behind.
    tmp="$dir.tmp.$$"
    rm -rf "$tmp"
    trap 'rm -rf "$tmp"' INT TERM
    git init -q "$tmp"
    git -C "$tmp" fetch -q --depth 1 "https://github.com/dcccrypto/$repo.git" "$pin" \
      && git -C "$tmp" checkout -q --detach FETCH_HEAD \
      || { rm -rf "$tmp"; echo "FATAL: could not fetch $repo @ $pin"; exit 1; }
    mv "$tmp" "$dir"
    trap - INT TERM
    echo "  fetched $1 @ ${pin:0:8}"
  fi
}

echo "== sibling checkouts in $WS (ci/deployed-refs.env)"
checkout percolator                    percolator       "$ENGINE_CI_SIBLING"
checkout percolator-nft                percolator-nft   "$NFT_CI_SIBLING"
checkout percolator-stake              percolator-stake "$STAKE_DEPLOYED"
checkout percolator-match              percolator-match "$MATCHER_DEPLOYED"
checkout percolator-match-p2           percolator-match "$MATCHER_P2_CI_SIBLING"
checkout percolator-match-v1           percolator-match "$MATCHER_V1_CI_SIBLING"
checkout growth-base/percolator-prog   percolator-prog  "$GROWTH_BASE_WRAPPER"
checkout growth-base/percolator        percolator       "$GROWTH_BASE_ENGINE"

# Platform-tools v1.52 and v1.54 both ship rustc 1.89.0, so cargo's fingerprints do not notice a toolchain switch
# and reuse the other toolchain's SBF deps. Measured: after one cargo-build-sbf 4.x build, 3.1.15 relinked
# matcher/stake against them and 806 tests failed with ProgramFailedToComplete. A stamp cannot see a build done
# by hand outside this script, so the SBF outputs are wiped on every run (costs about a minute of rebuild).
# Cargo.lock is not tracked at every pin (stake 53f54803): CI resolves it fresh, so a leftover one goes too.
for d in "$ROOT" "$WS/percolator-match" "$WS/percolator-nft" "$WS/percolator-stake" "$WS/percolator-match-p2" "$WS/percolator-match-v1"; do
  rm -rf "$d/target/sbpf-solana-solana"
  rm -f "$d"/target/deploy/percolator_{prog,match,nft,stake}.so
  if [ "$d" != "$ROOT" ] && ! git -C "$d" ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then rm -f "$d/Cargo.lock"; fi
done

keep=(PATH="$PATH" HOME="$HOME" USER="${USER:-}" TMPDIR="${TMPDIR:-/tmp}" TERM="${TERM:-dumb}")
for v in CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN CARGO_BUILD_JOBS SSH_AUTH_SOCK; do
  if [ -n "${!v:-}" ]; then keep+=("$v=${!v}"); fi
done

# Reference programs (v1 matcher, P2 matcher, v2.1 growth-base wrapper). Rebuilt when a pin, the build script
# or the toolchain changed: the growth-base build is the slow one and ci-build-test-artifacts.sh deletes its target.
# The keep/ci_env lists are defined below; this build gets the same clean environment as the suite.
SO="$WS/test-so"
stamp="$MATCHER_V1_CI_SIBLING $MATCHER_P2_CI_SIBLING $GROWTH_BASE_WRAPPER $GROWTH_BASE_ENGINE $(git hash-object "$ROOT/scripts/ci-build-test-artifacts.sh") $deploy_tc"
if [ -s "$SO/v1-matcher.so" ] && [ -s "$SO/p2-matcher.so" ] && [ -s "$SO/growth-base.so" ] \
   && [ "$(cat "$SO/.pins" 2>/dev/null)" = "$stamp" ]; then
  echo "== reference programs up to date in $SO"
else
  echo "== building reference programs into $SO"
  rm -f "$SO/.pins"
  env -i "${keep[@]}" "$ROOT/scripts/ci-build-test-artifacts.sh" "$WS" "$SO"
  echo "$stamp" > "$SO/.pins"
fi

echo "== suite toolchain: $deploy_tc (CI: agave v4.2.2 on Linux, see header)"

# The values of the `run suite and diff against the allowlist` step in .github/workflows/ci.yml, nothing else.
ci_env=(
  NFT_PIN=ci_sibling
  GROWTH_BASE_SO="$SO/growth-base.so"
  V1_MATCHER_SO="$SO/v1-matcher.so"
  INDEP_V1_MATCHER_SO="$SO/v1-matcher.so"
  INDEP_P2_MATCHER_SO="$SO/p2-matcher.so"
  P2_MATCHER_SO="$WS/percolator-match/target/deploy/percolator_match.so"
  CI_TEST_ARTIFACTS_REQUIRED=1
)

if [ "$setup_only" = 1 ]; then
  echo "== setup done. Run the suite with:"
  printf '  env -i'; printf ' %q' "${keep[@]}" "${ci_env[@]}"; printf ' %q\n' "$ROOT/scripts/ci-test.sh"
  exit 0
fi
echo "== scripts/ci-test.sh (builds match/nft/stake/match-p2 and the wrapper, runs the suite, diffs tests/KNOWN_FAILING.txt)"
cd "$ROOT"
exec env -i "${keep[@]}" "${ci_env[@]}" "$ROOT/scripts/ci-test.sh"
