//! Solver-capability probes (agent WRAP, 2026-10-20). Pure u128 arithmetic, no production code.
//! Each probe is a calibration question, decided once per solver; the answers choose the encoding of
//! the real lemma harnesses in kani/money. A probe verdict is never counted as a production proof.
#![no_std]

#[cfg(kani)]
mod probes {
    /// PR1: distributivity, modular (wrapping) u128.
    #[kani::proof]
    fn pr1_distrib_wrapping_u128() {
        let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
        assert!(x.wrapping_add(y).wrapping_mul(z) == x.wrapping_mul(z).wrapping_add(y.wrapping_mul(z)));
        kani::cover!(x > 1 && y > 1 && z > 1, "nontrivial");
    }

    /// PR2: the W-C-5 algebra over SHARED product terms (no ring identity left for the solver):
    /// given ab = a*B, vb = V*B, mv = m*V (each checked), mv <= ab, the expanded sums satisfy
    /// vb + mv <= vb + ab. Linear over the product outputs.
    #[kani::proof]
    fn pr2_shared_products_linear_u128() {
        let (a, b, v, m): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
        let (Some(ab), Some(vb), Some(mv)) = (a.checked_mul(b), v.checked_mul(b), m.checked_mul(v)) else { return };
        kani::assume(mv <= ab);
        if let (Some(x), Some(y)) = (vb.checked_add(ab), vb.checked_add(mv)) {
            assert!(y <= x);
            kani::cover!(y < x && m > 0, "strict");
        }
    }

    /// PR3: Rust `/` floor relation at full u128, quotient multiplied as q*d.
    #[kani::proof]
    fn pr3_div_floor_rel_qd_u128() {
        let (p, d): (u128, u128) = (kani::any(), kani::any());
        kani::assume(d > 0);
        let q = p / d;
        let qd = q.checked_mul(d);
        assert!(qd.is_some_and(|qd| qd <= p && p - qd < d));
        kani::cover!(p % d != 0 && q > 1 && d > 1, "inexact");
    }

    /// PR4: as PR3 with the product written d*q (CBMC's divider multiplies op1*res).
    #[kani::proof]
    fn pr4_div_floor_rel_dq_u128() {
        let (p, d): (u128, u128) = (kani::any(), kani::any());
        kani::assume(d > 0);
        let q = p / d;
        let dq = d.checked_mul(q);
        assert!(dq.is_some_and(|dq| dq <= p && p - dq < d));
        kani::cover!(p % d != 0 && q > 1 && d > 1, "inexact");
    }

    /// PR5: integer distributivity under no-overflow (checked ops), u128: the step that turns
    /// the factored claim into the expanded one.
    #[kani::proof]
    fn pr5_distrib_checked_u128() {
        let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
        if let (Some(s), Some(xz), Some(yz)) = (x.checked_add(y), x.checked_mul(z), y.checked_mul(z)) {
            if let (Some(l), Some(r)) = (s.checked_mul(z), xz.checked_add(yz)) {
                assert!(l == r);
                kani::cover!(x > 1 && y > 1 && z > 1, "nontrivial");
            }
        }
    }

    /// PR6: commutativity (checked), u128.
    #[kani::proof]
    fn pr6_comm_checked_u128() {
        let (x, y): (u128, u128) = (kani::any(), kani::any());
        assert!(x.checked_mul(y) == y.checked_mul(x));
        kani::cover!(x > 1 && y > 1 && x.checked_mul(y).is_some(), "nontrivial");
    }

    // ── batch 2: the ghost-lemma composition machinery ────────────────────────────────────
    /// Ghost lemma: modular distributivity (empty body; the ensures IS the lemma).
    #[kani::ensures(|_: &()| x.wrapping_add(y).wrapping_mul(z) == x.wrapping_mul(z).wrapping_add(y.wrapping_mul(z)))]
    fn lem_dist_wrap(x: u128, y: u128, z: u128) {}

    /// Ghost lemma: modular commutativity.
    #[kani::ensures(|_: &()| x.wrapping_mul(y) == y.wrapping_mul(x))]
    fn lem_comm_wrap(x: u128, y: u128) {}

    /// PR7a: prove the distributivity lemma's contract (z3 expected instant, as PR1).
    #[kani::proof_for_contract(lem_dist_wrap)]
    fn pr7a_lem_dist_wrap() {
        lem_dist_wrap(kani::any(), kani::any(), kani::any());
    }

    /// PR8a: prove the commutativity lemma's contract.
    #[kani::proof_for_contract(lem_comm_wrap)]
    fn pr8a_lem_comm_wrap() {
        lem_comm_wrap(kani::any(), kani::any());
    }

    /// PR7b: PR5 (checked integer distributivity) from the stubbed lemma + linear reasoning.
    #[kani::proof]
    #[kani::stub_verified(lem_dist_wrap)]
    fn pr7b_checked_distrib_via_lemma() {
        let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
        lem_dist_wrap(x, y, z);
        if let (Some(s), Some(xz), Some(yz)) = (x.checked_add(y), x.checked_mul(z), y.checked_mul(z)) {
            if let (Some(l), Some(r)) = (s.checked_mul(z), xz.checked_add(yz)) {
                assert!(l == r);
                kani::cover!(x > 1 && y > 1 && z > 1, "nontrivial");
            }
        }
    }

    /// PR8b: the W-C-5 factored claim from the floor fact, via both lemmas (full u128):
    /// m*V <= a*B  =>  (V+a)*B >= (B+m)*V whenever both factored products are representable.
    #[kani::proof]
    #[kani::stub_verified(lem_dist_wrap)]
    #[kani::stub_verified(lem_comm_wrap)]
    fn pr8b_floor_mint_no_dilution_via_lemmas() {
        let (a, b, v, m): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
        let (Some(ab), Some(mv)) = (a.checked_mul(b), m.checked_mul(v)) else { return };
        kani::assume(mv <= ab);
        lem_dist_wrap(v, a, b); // (V+a)*B == V*B + a*B
        lem_dist_wrap(b, m, v); // (B+m)*V == B*V + m*V
        lem_comm_wrap(v, b);    // V*B == B*V
        if let (Some(va), Some(bm)) = (v.checked_add(a), b.checked_add(m)) {
            if let (Some(lhs), Some(rhs)) = (va.checked_mul(b), bm.checked_mul(v)) {
                // the two expanded sums do not wrap: each summand <= the representable total
                assert!(lhs >= rhs, "incumbents not diluted");
                kani::cover!(lhs > rhs && m > 0, "strict");
            }
        }
    }

    /// PR9: the value of a non-overflowing checked_mul IS the wrapping product.
    #[kani::proof]
    fn pr9_checked_value_is_wrapping() {
        let (x, y): (u128, u128) = (kani::any(), kani::any());
        if let Some(v) = x.checked_mul(y) {
            assert!(v == x.wrapping_mul(y));
            kani::cover!(x > 1 && y > 1, "nontrivial");
        }
    }

    /// PR10: monotonicity of multiplication (checked), u128.
    #[kani::proof]
    fn pr10_mono_checked_u128() {
        let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
        kani::assume(x <= y);
        if let Some(yz) = y.checked_mul(z) {
            let xz = x.checked_mul(z);
            assert!(xz.is_some_and(|xz| xz <= yz));
            kani::cover!(x < y && z > 1 && x > 1, "nontrivial");
        }
    }

    /// PR11: overflow characterisation by division: z > 0 => (x*z fits <=> x <= MAX / z).
    #[kani::proof]
    fn pr11_overflow_iff_div_u128() {
        let (x, z): (u128, u128) = (kani::any(), kani::any());
        kani::assume(z > 0);
        assert!(x.checked_mul(z).is_some() == (x <= u128::MAX / z));
        kani::cover!(x.checked_mul(z).is_none() && x > 1 && z > 1, "overflow");
    }
}

