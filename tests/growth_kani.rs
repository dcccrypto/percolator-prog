//! growth-v19 Kani harnesses that need the full wrapper crate (instruction wire, P1 fee
//! allocation). Design: ~/percolator-ops/ledger/kani-growth-v19-design-2026-10-04.md rev 5
//! (R6 wire round trip, R15d fee-channel conservation). Run once, locally:
//!   cargo kani --tests --harness <name>
#![cfg(kani)]

extern crate kani;

use percolator_prog::ix::Instruction;
use percolator_prog::risk_limits_v17::allocate_fee_with_lp_request;

/// R6 (tag 94): InitVaultLpV19 round-trips; l_launch 0 and any other trailer length refuse.
#[kani::proof]
fn kani_growth_r6_tag94_v19_roundtrip() {
    let f: u16 = kani::any();
    let l: u16 = kani::any();
    let ix = Instruction::InitVaultLpV19 { junior_floor_bps: f, l_launch_x100: l };
    let b = ix.encode();
    assert_eq!(b.len(), 5);
    let d = Instruction::decode(&b);
    if l == 0 {
        assert!(d.is_err());
    } else {
        assert!(d.unwrap() == ix);
    }
    // 1 extra byte (an odd trailer) never decodes as the growth form
    let mut odd = [0u8; 4];
    odd.copy_from_slice(&b[..4]);
    assert!(!matches!(Instruction::decode(&odd), Ok(Instruction::InitVaultLpV19 { .. })));
    kani::cover!(l != 0, "round trip");
    kani::cover!(l == 0, "l_launch 0 refused");
}

/// R6 (tag 93): SetAssetRiskLimitsV19 round-trips in BOTH trailer forms (6 bytes: util 0 /
/// unchanged; 8 bytes: util != 0); an 8-byte trailer carrying util 0 refuses.
#[kani::proof]
fn kani_growth_r6_tag93_v19_roundtrip() {
    let limits = Instruction::SetAssetRiskLimits {
        asset_index: kani::any(),
        exec_band_bps: kani::any(),
        lp_exposure_k_bps: kani::any(),
        lp_floor_atoms: kani::any(),
        side_oi_cap_q: kani::any(),
        matcher_ext_mode: kani::any(),
        max_requested_fee_bps: kani::any(),
    };
    let util: u16 = kani::any();
    let ix = Instruction::SetAssetRiskLimitsV19 {
        limits: Box::new(limits.clone()),
        growth_lambda_bps: kani::any(),
        growth_kink_bps: kani::any(),
        growth_util_fee_max_bps: util,
    };
    let b = ix.encode();
    assert_eq!(b.len(), if util == 0 { 50 } else { 52 });
    assert!(Instruction::decode(&b).unwrap() == ix);
    // the legacy body alone decodes as the legacy instruction
    assert!(Instruction::decode(&b[..44]).unwrap() == limits);
    if util != 0 {
        let mut z = b.clone();
        z[50] = 0;
        z[51] = 0;
        assert!(Instruction::decode(&z).is_err());
    }
    kani::cover!(util == 0, "6-byte form");
    kani::cover!(util != 0, "8-byte form");
}

/// R15d: the P2 LP-credit allocation the utilisation fee travels in. Conservation, the base
/// split covered first (taker first, then the maker fallback), and everything beyond the base
/// credited to the LP from either side. u64 fees, full-range base.
#[kani::proof]
fn kani_growth_r15d_fee_channel_conservation() {
    let fa: u64 = kani::any();
    let fb: u64 = kani::any();
    let base: u64 = kani::any();
    let (ba, bb, lp) = allocate_fee_with_lp_request(fa as u128, fb as u128, base as u128);
    let total = fa as u128 + fb as u128;
    assert_eq!(ba + bb + lp, total);
    assert_eq!(ba + bb, total.min(base as u128));
    assert!(ba <= fa as u128 && bb <= fb as u128);
    assert!(bb == 0 || ba == fa as u128, "maker pays base only after the taker is exhausted");
    kani::cover!(fb > 0 && ba == fa as u128 && bb > 0 && lp > 0, "maker fallback: LP pays shortfall, credited back the excess");
    kani::cover!(fb == 0 && lp > 0, "taker pays base + util, LP credited");
    kani::cover!(lp == 0 && total > 0, "base only");
}
