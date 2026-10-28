#!/usr/bin/env bash
# CROSS-PROGRAM PARITY -- does the SHIPPED PAIR agree?
#
# WHY THIS EXISTS
#
# percolator-prog, percolator-stake and percolator-nft are each internally consistent and
# each suite is green, and the pair that actually runs on chain is still wrong, because
# nothing anywhere compares them. Two live examples:
#
#   * percolator-prog#441 -- the wrapper pins StakePool v3/392B, stake `main` emits v4/408B.
#     The DEPLOYED pair agrees, so devnet is fine; main-to-main does not, so the next
#     one-sided stake deploy breaks tag 87's staker fee leg. No suite saw it.
#
#   * The P5 deploy (2026-08-27) shipped nft `main` (cf56ba5) over the previously deployed
#     f18da24, reverting BOTH "accept wrapper VERSION 17" (ce6b051) and the wrapper-allowlist
#     id (58911ab). The deployed nft requires wrapper header VERSION 16 while the deployed
#     wrapper stamps 17, and its fail-closed allowlist names a wrapper that is not the one
#     running. The whole NFT feature is inert on devnet. No suite saw that either.
#
# So this script compares CONSTANTS ACROSS REPOS, per shippable pair.
#
# EVERYTHING IS READ OUT OF GIT AT AN EXPLICIT REF (`git show <ref>:<path>`), never from a
# working tree. A working tree can be dirty, and our local percolator-prog `main` is stale at
# 9d9164ca and does not even contain STAKE_POOL_VERSION -- anything comparing against a local
# main compares against nothing.
#
# ANTI-VACUITY IS THE WHOLE POINT
#
# A regex that silently misses turns every comparison below into ""=="" and the script becomes
# decorative. That exact mistake has already been made on this project. So every extractor
# HARD FAILS (exit 2, "EXTRACTOR MISSED") when it does not match, every integer is revalidated
# as digits-only, every pubkey as base58 of the right length, the number of extracted
# constants is asserted against an expected total, and so is the number of rows compared.
#
# VERDICT
#
#   * a row that DIVERGES and is not in tests/KNOWN_PARITY_DIVERGENCE.txt  -> RED (regression)
#   * a row that AGREES but IS in that file                                -> RED (delete it)
#   * an extractor that missed, or a ref that does not resolve             -> RED (exit 2)
#
# The second rule is what makes this self-cleaning: when the nft is redeployed with the fix,
# the nft rows start agreeing and CI goes red until the entries are removed. A silently-green
# CI is the failure mode this file exists to eliminate.
#
# USAGE
#   scripts/parity-check.sh
#   REF_NFT_DEPLOYED=<sha> scripts/parity-check.sh    # override one ref (demonstration/debug)
#   STAKE_REPO=/path NFT_REPO=/path scripts/parity-check.sh
#
# Written for bash 3.2 (macOS) as well as CI's bash 5 -- no associative arrays.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WRAPPER_REPO="${WRAPPER_REPO:-$ROOT}"
STAKE_REPO="${STAKE_REPO:-$ROOT/../percolator-stake}"
NFT_REPO="${NFT_REPO:-$ROOT/../percolator-nft}"

die() { printf '::error::%s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------------------------------
# REFS -- from the canonical file, overridable by env for demonstration.
# ---------------------------------------------------------------------------------------
REFS_FILE="$ROOT/ci/deployed-refs.env"
[ -r "$REFS_FILE" ] || die "$REFS_FILE missing -- the deployed refs have no source of truth"
# shellcheck disable=SC1090
set -a; . "$REFS_FILE"; set +a

REF_WRAPPER_DEPLOYED="${REF_WRAPPER_DEPLOYED:-$WRAPPER_DEPLOYED}"
REF_STAKE_DEPLOYED="${REF_STAKE_DEPLOYED:-$STAKE_DEPLOYED}"
REF_NFT_DEPLOYED="${REF_NFT_DEPLOYED:-$NFT_DEPLOYED}"

# The CANDIDATE pair is "what would be on chain if we deployed everything on main today".
# The wrapper side is HEAD -- in CI that is the PR's merge commit, i.e. the tree under
# review; it is still a real commit object, so this is `git show`, not a working-tree read.
REF_WRAPPER_CANDIDATE="${REF_WRAPPER_CANDIDATE:-HEAD}"
# A release branch may pin its shipping stake / nft in ci/deployed-refs.env (STAKE_CANDIDATE /
# NFT_CANDIDATE); otherwise the candidates are stake / nft `main`.
REF_STAKE_CANDIDATE="${REF_STAKE_CANDIDATE:-${STAKE_CANDIDATE:-origin/main}}"
REF_NFT_CANDIDATE="${REF_NFT_CANDIDATE:-${NFT_CANDIDATE:-origin/main}}"

KNOWN="${KNOWN:-$ROOT/tests/KNOWN_PARITY_DIVERGENCE.txt}"

# ---------------------------------------------------------------------------------------
# GIT + EXTRACTION. Every failure here is exit 2, never a silent empty string.
# ---------------------------------------------------------------------------------------

# resolve <repo> <ref> -> full sha (fetches once if the object is not local)
resolve() {
  local repo="$1" ref="$2" sha
  sha="$(git -C "$repo" rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null)" || true
  if [ -z "$sha" ]; then
    git -C "$repo" fetch --no-tags --quiet origin "$ref" >/dev/null 2>&1 || true
    sha="$(git -C "$repo" rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null)" || true
  fi
  [ -n "$sha" ] || die "ref '$ref' does not resolve in $repo -- the comparison it feeds would be vacuous"
  printf '%s' "$sha"
}

# blob <repo> <ref> <path> -> contents (never empty)
#
# NOTE THE BRACES in "${ref}:${path}". In zsh a bare  $ref:src/foo.rs  is parsed as a
# history-modifier expansion and silently mangles the argument into a nonexistent path --
# exactly the kind of silent miss this file exists to prevent. It bit me while writing it.
blob() {
  local repo="$1" ref="$2" path="$3" out
  out="$(git -C "$repo" show "${ref}:${path}" 2>/dev/null)" || true
  [ -n "$out" ] || die "EXTRACTOR MISSED: cannot read ${path} at ${ref} in ${repo}"
  printf '%s' "$out"
}

MISSED="This is NOT a parity failure -- the regex no longer matches the source, which would make every comparison using it VACUOUS. Fix the extractor before trusting any result from this script."

# rust_int <text> <CONST_NAME> <label> -> the integer literal of `[pub] const NAME: T = N;`
rust_int() {
  local text="$1" name="$2" label="$3" v
  v="$(printf '%s\n' "$text" \
       | sed -nE "s/^[[:space:]]*(pub[[:space:]]+)?const ${name}[[:space:]]*:[^=]*=[[:space:]]*([0-9_]+)[[:space:]]*;.*\$/\\2/p" \
       | head -1 | tr -d '_')"
  [ -n "$v" ] || die "EXTRACTOR MISSED: const ${name} (${label}). ${MISSED}"
  case "$v" in *[!0-9]*) die "EXTRACTOR MISSED: const ${name} (${label}) parsed as '${v}', not an integer";; esac
  printf '%s' "$v"
}

# rust_const_assert_eq <text> <CONST_NAME> <label> -> N from `assert!(NAME == N);`
# Used for STAKE_POOL_SIZE, which is `size_of::<StakePool>()` and therefore has no literal
# anywhere else; the const-assert is the only written-down number AND it is compiler-enforced.
rust_const_assert_eq() {
  local text="$1" name="$2" label="$3" v
  v="$(printf '%s\n' "$text" \
       | sed -nE "s/^[[:space:]]*assert!\\(${name}[[:space:]]*==[[:space:]]*([0-9_]+)\\);.*\$/\\1/p" \
       | head -1 | tr -d '_')"
  [ -n "$v" ] || die "EXTRACTOR MISSED: const-assert ${name} (${label}). ${MISSED}"
  case "$v" in *[!0-9]*) die "EXTRACTOR MISSED: const-assert ${name} (${label}) parsed as '${v}', not an integer";; esac
  printf '%s' "$v"
}

# rust_pubkey <text> <CONST_NAME> <label> -> base58 key from `const NAME: Pubkey = pubkey!("..")`
# The declaration spans two lines, so the text is flattened first.
rust_pubkey() {
  local text="$1" name="$2" label="$3" v n
  v="$(printf '%s\n' "$text" | tr '\n' ' ' \
       | sed -nE "s/.*const ${name}[^=]*=[[:space:]]*[a-z_:]*pubkey!\\(\"([1-9A-HJ-NP-Za-km-z]+)\"\\).*/\\1/p" \
       | head -1)"
  [ -n "$v" ] || die "EXTRACTOR MISSED: pubkey const ${name} (${label}). ${MISSED}"
  case "$v" in
    *[!123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*)
      die "EXTRACTOR MISSED: ${name} (${label}) parsed as '${v}', not base58";;
  esac
  n=${#v}
  { [ "$n" -ge 32 ] && [ "$n" -le 44 ]; } || die "EXTRACTOR MISSED: ${name} (${label}) parsed as '${v}' (len ${n}), not a 32-byte key"
  printf '%s' "$v"
}

# ---------------------------------------------------------------------------------------
# FACTS. Printed as shell assignments and eval'd, so this works on bash 3.2 (no assoc arrays).
# A non-zero exit from any extractor aborts the whole script -- it never becomes an empty var.
# ---------------------------------------------------------------------------------------
wrapper_facts() { # <ref> <prefix>
  local ref="$1" p="$2" src a b c
  src="$(blob "$WRAPPER_REPO" "$ref" src/v16_program.rs)" || return 2
  # Each extractor is captured and its status checked, so the FIRST miss aborts the run.
  # (`die` exits the command-substitution subshell; `|| return 2` turns that into a real
  # abort instead of letting an empty value flow into a comparison.)
  a="$(rust_int "$src" STAKE_POOL_VERSION "wrapper@${ref}")" || return 2
  b="$(rust_int "$src" STAKE_POOL_LEN     "wrapper@${ref}")" || return 2
  c="$(rust_int "$src" VERSION            "wrapper@${ref} account header")" || return 2
  echo "${p}STAKE_POOL_VERSION='$a'"
  echo "${p}STAKE_POOL_LEN='$b'"
  echo "${p}VERSION='$c'"
}

stake_facts() { # <ref> <prefix>
  local ref="$1" p="$2" src a b
  src="$(blob "$STAKE_REPO" "$ref" src/state.rs)" || return 2
  # CURRENT_VERSION is nested inside `impl StakePool`, so it is indented. The equivalent gate
  # check got this wrong on its first pass (top-level-only pattern, zero hits, vacuous test).
  a="$(rust_int "$src" CURRENT_VERSION "stake@${ref}")" || return 2
  b="$(rust_const_assert_eq "$src" STAKE_POOL_SIZE "stake@${ref}")" || return 2
  echo "${p}CURRENT_VERSION='$a'"
  echo "${p}STAKE_POOL_SIZE='$b'"
}

nft_facts() { # <ref> <prefix>
  local ref="$1" p="$2" slab cpi a b c
  slab="$(blob "$NFT_REPO" "$ref" src/slab_types_v16.rs)" || return 2
  cpi="$(blob "$NFT_REPO" "$ref" src/cpi_v16.rs)" || return 2
  a="$(rust_int "$slab" VERSION "nft@${ref} vendored wrapper header")" || return 2
  b="$(rust_pubkey "$cpi" PERCOLATOR_DEVNET  "nft@${ref} allowlist")" || return 2
  c="$(rust_pubkey "$cpi" PERCOLATOR_MAINNET "nft@${ref} allowlist")" || return 2
  echo "${p}VERSION='$a'"
  echo "${p}PERCOLATOR_DEVNET='$b'"
  echo "${p}PERCOLATOR_MAINNET='$c'"
}

load() { # load <fn> <ref> <prefix>
  local out
  out="$("$1" "$2" "$3")" || exit 2
  [ -n "$out" ] || die "$1 at $2 produced nothing"
  eval "$out"
}

echo "::group::resolved refs"
SHA_W_D="$(resolve "$WRAPPER_REPO" "$REF_WRAPPER_DEPLOYED")"  || exit 2
SHA_S_D="$(resolve "$STAKE_REPO"   "$REF_STAKE_DEPLOYED")"    || exit 2
SHA_N_D="$(resolve "$NFT_REPO"     "$REF_NFT_DEPLOYED")"      || exit 2
SHA_W_C="$(resolve "$WRAPPER_REPO" "$REF_WRAPPER_CANDIDATE")" || exit 2
SHA_S_C="$(resolve "$STAKE_REPO"   "$REF_STAKE_CANDIDATE")"   || exit 2
SHA_N_C="$(resolve "$NFT_REPO"     "$REF_NFT_CANDIDATE")"     || exit 2
printf '  DEPLOYED   wrapper %s\n             stake   %s\n             nft     %s\n' "$SHA_W_D" "$SHA_S_D" "$SHA_N_D"
printf '  CANDIDATE  wrapper %s\n             stake   %s\n             nft     %s\n' "$SHA_W_C" "$SHA_S_C" "$SHA_N_C"
echo "::endgroup::"

load wrapper_facts "$SHA_W_D" D_W_
load stake_facts   "$SHA_S_D" D_S_
load nft_facts     "$SHA_N_D" D_N_
load wrapper_facts "$SHA_W_C" C_W_
load stake_facts   "$SHA_S_C" C_S_
load nft_facts     "$SHA_N_C" C_N_

FACTS="D_W_STAKE_POOL_VERSION D_W_STAKE_POOL_LEN D_W_VERSION
D_S_CURRENT_VERSION D_S_STAKE_POOL_SIZE
D_N_VERSION D_N_PERCOLATOR_DEVNET D_N_PERCOLATOR_MAINNET
C_W_STAKE_POOL_VERSION C_W_STAKE_POOL_LEN C_W_VERSION
C_S_CURRENT_VERSION C_S_STAKE_POOL_SIZE
C_N_VERSION C_N_PERCOLATOR_DEVNET C_N_PERCOLATOR_MAINNET"
EXPECTED_FACTS=16

echo "::group::PROOF OF LIFE -- every constant was FOUND and parsed"
pol=0
for name in $FACTS; do
  eval "val=\${$name-}"
  [ -n "$val" ] || die "PROOF OF LIFE: ${name} is empty -- every comparison using it would be vacuous"
  printf '  %-26s = %s\n' "$name" "$val"
  pol=$((pol + 1))
done
[ "$pol" -eq "$EXPECTED_FACTS" ] || die "PROOF OF LIFE: validated ${pol} constants, expected ${EXPECTED_FACTS} -- an extractor was skipped"
echo "  ${pol}/${EXPECTED_FACTS} constants extracted and validated"
echo "::endgroup::"

# ---------------------------------------------------------------------------------------
# ROWS
# ---------------------------------------------------------------------------------------
EXPECTED_ROWS=9
rows=0
DIVERGED=""
AGREED=""

row() { # row <pair> <name> <lhs-label> <lhs> <rhs-label> <rhs>
  local pair="$1" name="$2" ll="$3" lv="$4" rl="$5" rv="$6"
  rows=$((rows + 1))
  if [ -z "$lv" ] || [ -z "$rv" ]; then
    die "row ${pair} ${name} has an EMPTY side (${ll}='${lv}' ${rl}='${rv}') -- vacuous comparison"
  fi
  if [ "$lv" = "$rv" ]; then
    printf '  %-10s %-22s AGREE    %s == %s == %s\n' "$pair" "$name" "$ll" "$lv" "$rl"
    AGREED="${AGREED}${pair} ${name}
"
  else
    printf '  %-10s %-22s DIVERGE  %s=%s  vs  %s=%s\n' "$pair" "$name" "$ll" "$lv" "$rl" "$rv"
    DIVERGED="${DIVERGED}${pair} ${name}
"
  fi
}

echo "::group::parity rows"
row DEPLOYED  stake.pool_version   wrapper.STAKE_POOL_VERSION "$D_W_STAKE_POOL_VERSION" stake.CURRENT_VERSION "$D_S_CURRENT_VERSION"
row DEPLOYED  stake.pool_len       wrapper.STAKE_POOL_LEN     "$D_W_STAKE_POOL_LEN"     stake.STAKE_POOL_SIZE "$D_S_STAKE_POOL_SIZE"
row DEPLOYED  nft.header_version   wrapper.VERSION            "$D_W_VERSION"            nft.VERSION           "$D_N_VERSION"
row DEPLOYED  nft.wrapper_allowlist deployed_wrapper_id       "$WRAPPER_PROGRAM_ID_DEVNET" nft.PERCOLATOR_DEVNET "$D_N_PERCOLATOR_DEVNET"
row CANDIDATE stake.pool_version   wrapper.STAKE_POOL_VERSION "$C_W_STAKE_POOL_VERSION" stake.CURRENT_VERSION "$C_S_CURRENT_VERSION"
row CANDIDATE stake.pool_len       wrapper.STAKE_POOL_LEN     "$C_W_STAKE_POOL_LEN"     stake.STAKE_POOL_SIZE "$C_S_STAKE_POOL_SIZE"
row CANDIDATE nft.header_version   wrapper.VERSION            "$C_W_VERSION"            nft.VERSION           "$C_N_VERSION"
row CANDIDATE nft.wrapper_allowlist deployed_wrapper_id       "$WRAPPER_PROGRAM_ID_DEVNET" nft.PERCOLATOR_DEVNET "$C_N_PERCOLATOR_DEVNET"
# The mainnet leg of the nft allowlist is not pair-specific -- the mainnet wrapper id is
# frozen (hard constraint #5), so any drift on either side is unambiguously a defect.
row SHARED    nft.mainnet_allowlist ledger_mainnet_id         "$WRAPPER_PROGRAM_ID_MAINNET" nft.PERCOLATOR_MAINNET "$D_N_PERCOLATOR_MAINNET"
echo "::endgroup::"

[ "$rows" -eq "$EXPECTED_ROWS" ] || die "compared ${rows} rows, expected ${EXPECTED_ROWS} -- a row was silently skipped"

# ---------------------------------------------------------------------------------------
# ci.yml pin hygiene -- there must be exactly ONE place a sibling pin is written down.
# ---------------------------------------------------------------------------------------
# This is the ONE deliberate working-tree read in this script. Every CROSS-REPO CONSTANT
# above comes out of git at an explicit ref, because a dirty tree must not be able to fake
# agreement. This check is the opposite shape: it is a property of the tree being PROPOSED,
# so reading it from git would make an uncommitted ci.yml edit invisible to the very check
# whose job is to police ci.yml. In CI the tree is the checked-out commit, so they coincide.
echo "::group::ci.yml pin hygiene"
CI_YML_PATH="$ROOT/.github/workflows/ci.yml"
[ -r "$CI_YML_PATH" ] || die "$CI_YML_PATH missing"
CI_YML="$(cat "$CI_YML_PATH")"
[ -n "$CI_YML" ] || die "$CI_YML_PATH is empty -- the hygiene check below would be vacuous"
printf '%s\n' "$CI_YML" | grep -q 'ci/deployed-refs.env' \
  || die "ci.yml does not read ci/deployed-refs.env -- the sibling pins have forked from the canonical file again, which is exactly how the stale nft pin survived"
# A literal SHA anywhere on a `ref:` line, quoted or not, terminated by a comma / brace /
# quote / end-of-line. The first version of this pattern anchored to end-of-line and missed
# `ref: 'd4d4f1c...', token: ...` -- the exact inline form it exists to catch. Verified
# against both the clean file (no match) and a deliberately re-inlined one (match).
stray="$(printf '%s\n' "$CI_YML" | grep -nE "ref:[[:space:]]*'?[0-9a-f]{7,40}('|[[:space:],}]|\$)" || true)"
[ -z "$stray" ] || die "ci.yml hardcodes a sibling SHA outside ci/deployed-refs.env:
${stray}"
echo "  ci.yml reads ci/deployed-refs.env and hardcodes no sibling SHA"
echo "::endgroup::"

# ---------------------------------------------------------------------------------------
# VERDICT
# ---------------------------------------------------------------------------------------
[ -r "$KNOWN" ] || die "$KNOWN missing -- without it every divergence would be unclassified"
known_list="$(grep -vE '^[[:space:]]*(#|$)' "$KNOWN" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | grep -v '^$' | sort -u)"
div_list="$(printf '%s' "$DIVERGED" | grep -v '^$' | sort -u)"
agr_list="$(printf '%s' "$AGREED"   | grep -v '^$' | sort -u)"

unexpected="$(comm -23 <(printf '%s\n' "$div_list" | grep -v '^$') <(printf '%s\n' "$known_list" | grep -v '^$'))"
now_agreeing="$(comm -12 <(printf '%s\n' "$agr_list" | grep -v '^$') <(printf '%s\n' "$known_list" | grep -v '^$'))"

echo
printf 'SUMMARY: %d rows -- %d agree, %d diverge, %d allowlisted\n' \
  "$rows" \
  "$(printf '%s\n' "$agr_list" | grep -c '[^[:space:]]')" \
  "$(printf '%s\n' "$div_list" | grep -c '[^[:space:]]')" \
  "$(printf '%s\n' "$known_list" | grep -c '[^[:space:]]')"

rc=0
if [ -n "$unexpected" ]; then
  echo "::error::UNEXPECTED cross-program divergence -- the shipped pair does not agree:"
  printf '%s\n' "$unexpected" | sed 's/^/    /'
  echo "    Do NOT add a row to tests/KNOWN_PARITY_DIVERGENCE.txt to make this green unless the"
  echo "    divergence is a deliberate, recorded, NON-SHIPPING state with the finding written down."
  rc=1
fi
if [ -n "$now_agreeing" ]; then
  echo "::error::allowlisted divergences now AGREE -- delete them from tests/KNOWN_PARITY_DIVERGENCE.txt:"
  printf '%s\n' "$now_agreeing" | sed 's/^/    /'
  echo "    This is the good failure: a known defect got fixed. Remove the row and the guard"
  echo "    turns into a regression test for the fix. Leaving it here re-hides the next one."
  rc=1
fi
[ $rc -eq 0 ] && echo "OK: divergence set matches tests/KNOWN_PARITY_DIVERGENCE.txt exactly"
exit $rc
