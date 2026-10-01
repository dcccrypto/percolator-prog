//! EXHAUSTIVE enumeration over small bounded domains of the exact production file — the same
//! bounded statement a Kani harness over those domains makes, discharged by enumeration because
//! CBMC could not finish the 128-bit nonlinear circuits in the watchdog budget. Every property
//! also asserts it was exercised (counters), so a vacuous pass is impossible.
use p3_vault_lp_proofs::vault_lp_v18::*;

#[test]
fn exhaustive_deposit_no_dilution_u8() {
    let (mut genesis, mut normal, mut refused) = (0u64, 0u64, 0u64);
    for amount in 0u128..=255 {
        for s in 0u128..=255 {
            for senior in 0u128..=255 {
                match senior_shares_for_deposit(amount, s, senior) {
                    Some(minted) => {
                        if s == 0 {
                            assert_eq!(minted, amount);
                            genesis += 1;
                        } else {
                            assert!((senior + amount) * s >= senior * (s + minted));
                            assert!(minted * senior <= amount * s);
                            normal += 1;
                        }
                    }
                    None => {
                        assert!(s != 0 && senior == 0);
                        refused += 1;
                    }
                }
            }
        }
    }
    println!("deposit: genesis {genesis} normal {normal} refused {refused}");
    assert!(genesis > 0 && normal > 0 && refused > 0);
}

#[test]
fn exhaustive_redemption_no_dilution_u5() {
    let (mut whole, mut impaired, mut last) = (0u64, 0u64, 0u64);
    for c in 0u128..32 {
        for v in 0u128..32 {
            for s in 1u128..32 {
                for shares in 0..=s {
                    for avail in 0u128..32 {
                        let senior = tranche_split(v, c).senior;
                        let payout = senior_atoms_for_redemption(shares, s, senior).unwrap();
                        let c_after = senior_claim_after_redemption(c, shares, s).unwrap();
                        assert!(payout <= senior);
                        assert!(c_after * s >= c * (s - shares));
                        if v >= c {
                            assert_eq!(payout, c - c_after);
                            whole += 1;
                        } else {
                            impaired += 1;
                        }
                        if shares == s {
                            last += 1;
                        }
                        let principal = senior_principal_portion(shares, avail, s, payout).unwrap();
                        assert!(principal <= payout);
                    }
                }
            }
        }
    }
    println!("redemption: whole {whole} impaired {impaired} last-redeemer {last}");
    assert!(whole > 0 && impaired > 0 && last > 0);
}

#[test]
fn exhaustive_exposure_cap_and_resolved_split() {
    let mut refused = 0u64;
    for before in -40i128..=40 {
        for after in -40i128..=40 {
            for equity in 0u128..=40 {
                for lev in [0u32, 5_000, 10_000, 20_000, 50_000] {
                    for price in [0u64, 1, 7, 1_000] {
                        let ok = vault_lp_exposure_allowed(before, after, equity, lev, price, 10);
                        if after.unsigned_abs() <= before.unsigned_abs() {
                            assert!(ok);
                        } else {
                            let notional = after.unsigned_abs() * price as u128 / 10;
                            assert_eq!(ok, notional <= equity * lev as u128 / 10_000);
                            if !ok {
                                refused += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(refused > 0);
    for p in 0u128..64 {
        for c in 0u128..64 {
            for n in 0u128..64 {
                let (b, j) = resolved_settle_split(p, c, n);
                assert_eq!(b + j, p);
                assert!(b <= c.saturating_sub(n));
                if j > 0 {
                    assert!(n + b >= c);
                }
            }
        }
    }
}
