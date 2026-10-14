#!/usr/bin/env python3
"""Write each planted mutant as a COPY of the production file with exactly ONE edit (asserts the
search string occurs exactly once). Production files are never modified. Run: python3 -I mkmutants.py"""
import pathlib, sys
here = pathlib.Path(__file__).resolve().parent
src = here.parent.parent / "src"
stake = here.parent.parent.parent / "percolator-stake" / "src"
M = [
 ("bond_v20_deposit.rs", src/"bond_v20.rs",
  "    mul_div_floor(amount, total_shares, bond_value)\n",
  "    mul_div_floor(amount, total_shares, bond_value).map(|m| m + 1) // MUTANT MB-1: deposit mints one share too many\n"),
 ("bond_v20_redeem.rs", src/"bond_v20.rs",
  "    mul_div_floor(shares, bond_value, total_shares)\n",
  "    mul_div_floor(shares, bond_value, total_shares).map(|p| p + 1) // MUTANT MB-2: redeemer paid one atom too many\n"),
 ("p4_rescue_shares.rs", src/"p4_rescue_ins.rs",
  "    mul_div_floor(x, s, v)\n",
  "    mul_div_floor(x, s, v).map(|m| m + 1) // MUTANT MR-1: rescuer gets one share too many\n"),
 ("p4_rescue_claim.rs", src/"p4_rescue_ins.rs",
  "    mul_div_floor(m, c, s)\n",
  "    mul_div_floor(m, c, s).map(|d| d + 1) // MUTANT MR-2: rescue raises par per share\n"),
 ("p4_ins_topup.rs", src/"p4_rescue_ins.rs",
  "    mul_div_floor(x, units_total, insurance_mint_reading)\n",
  "    mul_div_floor(x, units_total, insurance_mint_reading).map(|m| m + 1) // MUTANT MI-1: top-up mints one unit too many\n"),
 ("p4_ins_burn.rs", src/"p4_rescue_ins.rs",
  "    let b = mul_div_ceil(a, units_total, insurance_free)?;\n",
  "    let b = mul_div_floor(a, units_total, insurance_free)?; // MUTANT MI-2: burn rounds DOWN\n"),
 ("p4_ceil.rs", src/"p4_rescue_ins.rs",
  "    Some(p / d + u128::from(p % d != 0))\n",
  "    Some(p / d) // MUTANT MC-2: ceil primitive floors\n"),
 ("vault_lp_v18.rs", src/"vault_lp_v18.rs",
  "    a.checked_mul(b).map(|p| p / d)\n}\n\n/// Kani contract of `mul_div_floor`",
  "    a.checked_mul(b).map(|p| p.div_ceil(d)) // MUTANT MC-1: floor primitive rounds UP\n}\n\n/// Kani contract of `mul_div_floor`"),
 ("stake_math_topup.rs", stake/"math.rs",
  "    (a as u128).checked_mul(units_total).map(|p| p / insurance_mint)\n",
  "    (a as u128).checked_mul(units_total).map(|p| p.div_ceil(insurance_mint)) // MUTANT ME-1: stake expects ceil units\n"),
 ("p4_ins_value.rs", src/"p4_rescue_ins.rs",
  "    mul_div_floor(units, insurance, units_total)\n",
  "    mul_div_floor(units, insurance, units_total).map(|v| v + 1) // MUTANT MI-3: units over-valued by one atom\n"),
 ("stake_math_burn.rs", stake/"math.rs",
  "    Some(p.div_ceil(insurance_free))\n",
  "    Some(p / insurance_free) // MUTANT ME-2: stake expects a floored burn\n"),
 ("stake_math_value.rs", stake/"math.rs",
  "    let v = units_stake.checked_mul(insurance)? / units_total;\n",
  "    let v = units_stake.checked_mul(insurance)?.div_ceil(units_total); // MUTANT ME-3: stake value rounded up\n"),
]
for name, f, old, new in M:
    t = f.read_text()
    n = t.count(old)
    if n != 1:
        sys.exit(f"{name}: search string occurs {n} times in {f}")
    (here/"mutants"/name).write_text(t.replace(old, new))
    print(f"{name}: 1 edit from {f}")
