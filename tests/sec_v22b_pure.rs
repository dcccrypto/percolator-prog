#![cfg(not(kani))]
use percolator_prog::growth_v19::{band_lambda_max_bps, band_r_gap_bps, rent_rate_e9};

struct Rng(u64);
impl Rng {
    fn n(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn sec_rent_rate_exact_ceil_monotone_capped_and_no_overflow_in_domain() {
    let mut r = Rng(0x1234_5678_9abc_def1);
    let mut checked = 0u64;
    for _ in 0..2_000_000 {
        let n_cap = 1 + (r.n() as u128 % 100_000_000_000_000u128); // <= MAX_POSITION_ABS_Q 1e14
        let users = r.n() as u128 % (2 * n_cap);
        let kink = (r.n() % 10_001) as u16;
        let max = (r.n() % 10_001) as u64;
        let got = rent_rate_e9(users, n_cap, kink, max).expect("in-domain never None");
        assert!(got <= max);
        // exact reference (u128 is wide enough in this domain)
        let lhs = users * 10_000;
        let rhs = kink as u128 * n_cap;
        let want = if lhs <= rhs || max == 0 {
            0
        } else if users >= n_cap {
            max as u128
        } else {
            let num = max as u128 * (lhs - rhs);
            let den = n_cap * (10_000 - kink as u128);
            (num + den - 1) / den
        };
        assert_eq!(
            got as u128, want,
            "users={users} n={n_cap} kink={kink} max={max}"
        );
        // monotone in users
        let got2 = rent_rate_e9(users.saturating_add(1), n_cap, kink, max).unwrap();
        assert!(got2 >= got);
        // zero at or below the kink
        if users * 10_000 <= kink as u128 * n_cap {
            assert_eq!(got, 0);
        }
        checked += 1;
    }
    eprintln!("SEC rent_rate_e9 exact over {checked} random in-domain cases");
    // out-of-domain: checked_mul overflow returns None (callers map None -> 0 = FAIL-OPEN to no rent)
    assert_eq!(rent_rate_e9(u128::MAX, 1, 0, 23), None);
    assert_eq!(rent_rate_e9(u128::MAX / 10_000 + 1, 10, 0, 23), None);
    // kink > 100% and n_cap == 0 refused
    assert_eq!(rent_rate_e9(1, 0, 0, 23), None);
    assert_eq!(rent_rate_e9(1, 1, 10_001, 23), None);
    // quantisation cliff: just above the kink pays >= 1 unit = max/23 of the ceiling
    let just_above = rent_rate_e9(5_000_000_001, 10_000_000_000, 5_000, 23).unwrap();
    eprintln!("SEC rent cliff: u = kink + 1e-10 pays {just_above} of max 23 e9/slot");
    assert_eq!(just_above, 1);
}

#[test]
fn sec_band_lambda_max_and_r_gap_table() {
    for d in [60u64, 100, 130, 300] {
        let g = band_r_gap_bps(d).unwrap();
        for mmr in [250u64, 500, 1000] {
            let l = band_lambda_max_bps(mmr, g as u64).unwrap();
            eprintln!(
                "SEC d={d} G={g} MMR={mmr} -> lambda_max {} bps ({:.2}x)",
                l,
                l as f64 / 10_000.0
            );
        }
    }
}

/// Review W-M2: the mainnet build (no `devnet` feature) caps a band market's lambda at 3x and
/// alpha at 60%; the devnet build keeps 10x / 70%. Run this file both ways.
#[test]
fn sec_band_caps_by_build() {
    use percolator_prog::growth_v19 as gv;
    let (lambda, alpha) = if cfg!(feature = "devnet") {
        (100_000, 7_000)
    } else {
        (30_000, 6_000)
    };
    assert_eq!(gv::BAND_LAMBDA_CAP_BPS, lambda);
    assert_eq!(gv::ALLOC_ALPHA_MAX_BAND_BPS, alpha);
    for d in [60u64, 100, 130, 300] {
        let g = band_r_gap_bps(d).unwrap();
        for mmr in [1u64, 250, 500, 1000] {
            assert!(band_lambda_max_bps(mmr, g as u64).unwrap() <= lambda);
        }
    }
    assert_eq!(gv::alloc_alpha_max_bps(true), alpha);
    use percolator_prog::vault_lp_v18::{vault_lp_alloc_limit, ALLOC_BUFFER_MIN_BPS};
    assert!(vault_lp_alloc_limit(1_000_000, 0, 1_000_000, alpha, ALLOC_BUFFER_MIN_BPS).is_some());
    assert!(
        vault_lp_alloc_limit(1_000_000, 0, 1_000_000, alpha + 1, ALLOC_BUFFER_MIN_BPS).is_none(),
        "hard cap"
    );
}

#[test]
fn sec3_init_market_trailer_lengths_decode_only_on_the_grammar() {
    use percolator_prog::ix::{Instruction, InitMarketPhase4};
    // base InitMarket bytes (no trailer) from a V19 encode with the growth block stripped.
    let base_ix = Instruction::InitMarketV22 {
        market: Box::new(Instruction::InitMarket {
            max_portfolio_assets: 1, h_min: 1, h_max: 10, initial_price: 1_000_000,
            min_nonzero_mm_req: 1, min_nonzero_im_req: 2, maintenance_margin_bps: 500, initial_margin_bps: 1000,
            max_trading_fee_bps: 100, trade_fee_base_bps: 10, liquidation_fee_bps: 50, liquidation_fee_cap: 1_000_000,
            min_liquidation_abs: 0, max_price_move_bps_per_slot: 4, max_accrual_dt_slots: 1,
            max_abs_funding_e9_per_slot: 1, min_funding_lifetime_slots: 1, max_account_b_settlement_chunks: 1,
            max_bankrupt_close_chunks: 1, max_bankrupt_close_lifetime_slots: 10, public_b_chunk_atoms: 1_000, maintenance_fee_per_slot: 0,
        }),
        growth_r_gap_bps: 400, growth_l_launch_x100: 1000, lot_exp: 0,
        phase4: InitMarketPhase4 { rent_max_e9_per_slot: 23, rent_kink_bps: 5000, band_bps: 0, ..Default::default() },
    };
    let full = base_ix.encode();
    let Instruction::InitMarketV22 { market, .. } = &base_ix else { unreachable!() };
    let base_len = market.encode().len();
    let mut ok = vec![];
    for tl in 0..=34usize {
        let mut b = market.encode();
        // nonzero filler so a field of zero cannot hide an alias; band_bps byte pair = 130
        let filler: Vec<u8> = (0..tl).map(|i| match i { 0|1 => if i == 0 { 144 } else { 1 } , _ => 7 }).collect();
        b.extend_from_slice(&filler);
        if Instruction::decode(&b).is_ok() { ok.push(tl); }
    }
    eprintln!("SEC3 decodable trailer lengths (growth+rent+band, combined grammar incl. the lot byte): {ok:?}; base_len {base_len}, full {}", full.len());
    assert!(ok.iter().all(|l| [0usize, 4, 5, 10, 11, 28, 29].contains(l)), "only the grammar decodes: {ok:?}");
}
