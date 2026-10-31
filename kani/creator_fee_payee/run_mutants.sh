#!/usr/bin/env bash
# prog#587 negative controls: each mutant is one deliberate defect in a copy of the production
# file; the named harness must report VERIFICATION FAILED. A mutant whose edit does not apply,
# or whose harness still passes, makes this script exit non-zero.
set -uo pipefail
cd "$(dirname "$0")"
SRC=../../src/creator_fee_payee_v22.rs
OUT=mutants/creator_fee_payee_v22_mutant.rs
rc=0
mkdir -p mutants
mutate() { # name harness python-replace-old python-replace-new
  local name=$1 harness=$2 old=$3 new=$4
  python3 - "$SRC" "$OUT" "$old" "$new" <<'PY' || { echo "MUTANT $name: edit did not apply"; return 2; }
import sys
src, out, old, new = sys.argv[1:5]
s = open(src).read()
if s.count(old) != 1:
    sys.exit(1)
open(out, "w").write(s.replace(old, new))
PY
  if cargo kani -j 2 --output-format terse --features mutant --harness "$harness" >"mutants/$name.log" 2>&1; then
    echo "MUTANT $name ($harness): SURVIVED (harness passed) -- FAIL"; return 1
  fi
  if grep -q "VERIFICATION:- FAILED" "mutants/$name.log"; then
    echo "MUTANT $name ($harness): killed ($(grep -m1 -i 'failed' "mutants/$name.log" | head -c 160))"
  else
    echo "MUTANT $name ($harness): no FAILED verdict (build error?) -- see mutants/$name.log"; return 3
  fi
}
mutate route_inverted kani_587_claim_route_exact \
  '    if *asset_admin != [0u8; 32] {
        ClaimRoute::AdminSigned' \
  '    if *asset_admin == [0u8; 32] {
        ClaimRoute::AdminSigned' || rc=1
mutate burned_admin_can_set kani_587_payee_frozen_after_burn \
  '    *asset_admin != [0u8; 32]
        && *asset_admin == *signer' \
  '    *asset_admin == *signer' || rc=1
mutate vault_authority_payee_allowed kani_587_payee_frozen_after_burn \
  '        && *new_payee != *vault_authority
' \
  '' || rc=1
mutate orphan_takes_payee_pot kani_587_claim_route_exact \
  'pot != 0 && claim_route(asset_admin, payee_flag) == ClaimRoute::Refused' \
  'pot != 0 && claim_route(asset_admin, payee_flag) != ClaimRoute::AdminSigned' || rc=1
mutate bit_collides_with_bit2 kani_587_payee_bit_isolated \
  'pub const P4_FLAG_CREATOR_FEE_PAYEE: u8 = 1 << 3;' \
  'pub const P4_FLAG_CREATOR_FEE_PAYEE: u8 = 1 << 2;' || rc=1
mutate legacy_not_debited kani_587_claim_debit_conserves \
  'Some((asset_pot - from_asset, legacy_pot.checked_sub(from_legacy)?))' \
  'Some((asset_pot - from_asset, legacy_pot))' || rc=1
rm -f "$OUT"
exit $rc
