//! Reference-model property + boundary tests for `creator_fee_payee_v22` (integration test: the
//! reference model uses u128 / bool logic written from the doc comments, not the production bodies).
use percolator_prog::creator_fee_payee_v22::*;
use proptest::prelude::*;

const Z: [u8; 32] = [0u8; 32];

/// Keys drawn from a tiny alphabet so equal / zero / different all occur often.
fn key() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![Just(0u8), Just(1u8), Just(2u8), Just(3u8)].prop_map(|b| [b; 32])
}
/// u64 biased toward the edges.
fn edge_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX),
        Just(u64::MAX - 1),
        Just(CREATOR_PAYEE_GRACE_SLOTS),
        Just(u64::MAX - CREATOR_PAYEE_GRACE_SLOTS),
        Just(u64::MAX - CREATOR_PAYEE_GRACE_SLOTS + 1),
        any::<u64>(),
    ]
}

// ---- reference model ----------------------------------------------------------------
fn ref_route(admin_zero: bool, flag: bool) -> u8 {
    // 0 = AdminSigned, 1 = Payee, 2 = Refused
    match (admin_zero, flag) {
        (false, _) => 0,
        (true, true) => 1,
        (true, false) => 2,
    }
}
fn ref_grace(resolved: bool, rs: u64, now: Option<u64>) -> bool {
    match now {
        None => false,
        Some(n) => resolved && (rs as u128 + CREATOR_PAYEE_GRACE_SLOTS as u128) <= u64::MAX as u128
            && (n as u128) >= rs as u128 + CREATOR_PAYEE_GRACE_SLOTS as u128,
    }
}
fn ref_debit(a: u64, l: u64, amt: u64) -> Option<(u64, u64)> {
    let (a, l, amt) = (a as u128, l as u128, amt as u128);
    if amt == 0 || amt > a + l {
        return None;
    }
    let from_a = amt.min(a);
    let from_l = amt - from_a;
    Some(((a - from_a) as u64, (l - from_l) as u64))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn route_matches_model(admin in key(), flag: bool) {
        let want = ref_route(admin == Z, flag);
        let got = match claim_route(&admin, flag) {
            ClaimRoute::AdminSigned => 0, ClaimRoute::Payee => 1, ClaimRoute::Refused => 2 };
        prop_assert_eq!(got, want);
    }

    #[test]
    fn update_allowed_matches_model(admin in key(), signer in key(), cur in proptest::option::of(key()),
                                    new in key(), va in key()) {
        let want = admin != Z && signer == admin && new != Z && new != va && cur != Some(new);
        prop_assert_eq!(payee_update_allowed(&admin, &signer, cur.as_ref(), &new, &va), want);
        if admin == Z { prop_assert!(!payee_update_allowed(&admin, &signer, cur.as_ref(), &new, &va)); }
    }

    #[test]
    fn grace_matches_model(resolved: bool, rs in edge_u64(), now in proptest::option::of(edge_u64())) {
        prop_assert_eq!(payee_grace_elapsed(resolved, rs, now), ref_grace(resolved, rs, now));
    }

    /// Monotone in now, and exact boundary at resolved_slot + GRACE.
    #[test]
    fn grace_boundary_and_monotone(rs in 0u64..=(u64::MAX - CREATOR_PAYEE_GRACE_SLOTS), d in edge_u64()) {
        let end = rs + CREATOR_PAYEE_GRACE_SLOTS;
        prop_assert!(!payee_grace_elapsed(true, rs, Some(end - 1)));
        prop_assert!(payee_grace_elapsed(true, rs, Some(end)));
        let later = end.saturating_add(d);
        prop_assert!(payee_grace_elapsed(true, rs, Some(later)));
        prop_assert!(!payee_grace_elapsed(false, rs, Some(later)));
    }

    #[test]
    fn orphan_matches_model(admin in key(), flag: bool, pot in edge_u64(), over: bool) {
        let want = pot != 0 && match ref_route(admin == Z, flag) { 0 => false, 1 => over, _ => true };
        prop_assert_eq!(creator_pot_orphaned(&admin, flag, pot, over), want);
    }

    #[test]
    fn debit_matches_model(a in edge_u64(), l in edge_u64(), amt in edge_u64()) {
        prop_assert_eq!(split_claim_debit(a, l, amt), ref_debit(a, l, amt));
        if let Some((a2, l2)) = split_claim_debit(a, l, amt) {
            prop_assert_eq!((a as u128 + l as u128) - (a2 as u128 + l2 as u128), amt as u128);
            prop_assert!(a2 <= a && l2 <= l);
        }
    }

    /// Repeated claims never pay more than the pot: sum of paid <= initial total, and the
    /// counters never grow; once drained every further claim is None.
    #[test]
    fn repeated_claims_no_double_pay(a in edge_u64(), l in edge_u64(),
                                     amts in proptest::collection::vec(edge_u64(), 1..12)) {
        let total0 = a as u128 + l as u128;
        let (mut ca, mut cl, mut paid) = (a, l, 0u128);
        for amt in amts {
            if let Some((na, nl)) = split_claim_debit(ca, cl, amt) {
                prop_assert!(na <= ca && nl <= cl);
                paid += amt as u128;
                ca = na; cl = nl;
            }
            prop_assert!(paid <= total0);
            prop_assert_eq!(paid + ca as u128 + cl as u128, total0);
        }
        if ca == 0 && cl == 0 { prop_assert_eq!(split_claim_debit(ca, cl, 1), None); }
    }

    #[test]
    fn payee_bit_matches_model(flags: u8, on: bool) {
        let want = if on { flags | 8 } else { flags & 0xF7 };
        prop_assert_eq!(with_payee_bit(flags, on), want);
        prop_assert_eq!(has_payee_bit(flags), (flags >> 3) & 1 == 1);
        prop_assert_eq!(with_payee_bit(with_payee_bit(flags, on), on), want, "idempotent");
    }

    #[test]
    fn record_binds_matches_model(market in key(), payee in key(), idx in 0u16..4, q_market in key(),
                                  q_idx in 0u16..4, version in 0u8..3, res in 0u8..2, pos in 0usize..4) {
        let r = CreatorFeePayeeV22 { market, payee, asset_index: idx, version, bump: 1, _reserved: { let mut x = [0u8; 4]; x[pos] = res; x } };
        let valid = version == 1 && market != Z && payee != Z && res == 0;
        prop_assert_eq!(validate_creator_fee_payee(&r), valid);
        prop_assert_eq!(record_binds(&r, &q_market, q_idx), valid && market == q_market && idx == q_idx);
    }
}

// ---- boundaries ---------------------------------------------------------------------
#[test]
fn zero_fee_claims_refused() {
    assert_eq!(split_claim_debit(0, 0, 0), None);
    assert_eq!(split_claim_debit(5, 5, 0), None);
    assert_eq!(split_claim_debit(0, 0, 1), None);
    assert!(!creator_pot_orphaned(&Z, false, 0, true), "zero pot is never orphaned");
}

#[test]
fn max_values() {
    let m = u64::MAX;
    assert_eq!(split_claim_debit(m, m, m), Some((0, m)));
    assert_eq!(split_claim_debit(m, 0, m), Some((0, 0)));
    assert_eq!(split_claim_debit(0, m, m), Some((0, 0)));
    assert_eq!(split_claim_debit(m, m, m - 1), Some((1, m)));
    // total of two maxes is 2*m in u128: no overflow in the sum.
    assert_eq!(split_claim_debit(m, 1, m), Some((0, 1)));
}

#[test]
fn grace_exact_slot_and_rotation_window() {
    let rs = 123_456u64;
    let end = rs + CREATOR_PAYEE_GRACE_SLOTS;
    assert!(!payee_grace_elapsed(true, rs, Some(end - 1)));
    assert!(payee_grace_elapsed(true, rs, Some(end)));
    assert!(payee_grace_elapsed(true, rs, Some(end + 1)));
    // Payee rotation needs a live admin; a burned (zero) admin refuses every signer.
    assert!(!payee_update_allowed(&Z, &[1; 32], Some(&[2; 32]), &[3; 32], &[4; 32]));
    // resolved_slot at the exact overflow edge: end == u64::MAX is representable.
    let rs_edge = u64::MAX - CREATOR_PAYEE_GRACE_SLOTS;
    assert!(!payee_grace_elapsed(true, rs_edge, Some(u64::MAX - 1)));
    assert!(payee_grace_elapsed(true, rs_edge, Some(u64::MAX)));
    assert!(!payee_grace_elapsed(true, rs_edge + 1, Some(u64::MAX)));
}

#[test]
fn repeated_claim_drains_once() {
    let (a, l) = (7u64, 3u64);
    let (a, l) = split_claim_debit(a, l, 10).unwrap();
    assert_eq!((a, l), (0, 0));
    assert_eq!(split_claim_debit(a, l, 10), None);
    assert_eq!(split_claim_debit(a, l, 1), None);
}
