//! NATIVE (not Kani) cross-check of `depth_src_v22::pin_matches` against its conjunct list, run because the in-crate
//! Kani harness `kani_dex_pin_check_all_or_nothing` (and the split twins K-W-A2/K-W-A3) report FAILED while every
//! counterexample replays natively with `ok == all` (and the K-W-A3 replay even violates its own `assume`).
//! Keys are drawn from a 3-letter alphabet so that equalities of every conjunct are hit often.
use percolator_prog::depth_src_v22::*;

fn key(r: &mut u64) -> [u8; 32] {
    *r ^= *r << 13; *r ^= *r >> 7; *r ^= *r << 17;
    [(*r % 3) as u8; 32]
}
fn num(r: &mut u64, m: u64) -> u64 {
    *r ^= *r << 13; *r ^= *r >> 7; *r ^= *r << 17;
    *r % m
}

#[test]
fn pin_matches_equals_conjunct_list_random_small_alphabet() {
    let mut r: u64 = 0x9E3779B97F4A7C15;
    let (mut accepted, mut n) = (0u64, 0u64);
    let pumpswap = PUMPSWAP_AMM_PROGRAM_ID.to_bytes();
    for _ in 0..(1u64 << 24) {
        let flags = num(&mut r, 4) as u8;
        let owner_choice = num(&mut r, 3);
        let owner = if owner_choice == 0 { pumpswap } else { key(&mut r) };
        let pin = DepthSourceV22 {
            market: key(&mut r), amm_program: if num(&mut r, 2) == 0 { owner } else { key(&mut r) }, pool: key(&mut r),
            base_vault: key(&mut r), quote_vault: key(&mut r), base_mint: key(&mut r), quote_mint: key(&mut r),
            market_id: num(&mut r, 2), set_slot: 0, asset_index: num(&mut r, 2) as u16, base_decimals: 0, quote_decimals: 0,
            flags, version: DEPTH_SOURCE_VERSION, bump: 0, amm_kind: num(&mut r, 3) as u8, _reserved: [0; 8],
        };
        let t0 = if num(&mut r, 2) == 0 { None } else { Some(key(&mut r)) };
        let t1 = if num(&mut r, 2) == 0 { None } else { Some(key(&mut r)) };
        // bias the view toward the pin so acceptance is frequent
        let pick = |r: &mut u64, v: [u8; 32]| if num(r, 4) != 0 { v } else { key(r) };
        let (b, q) = if flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 { (1usize, 0usize) } else { (0, 1) };
        let mut vault = [[0u8; 32]; 2]; let mut mint = [[0u8; 32]; 2];
        vault[b] = pick(&mut r, pin.base_vault); vault[q] = pick(&mut r, pin.quote_vault);
        mint[b] = pick(&mut r, pin.base_mint); mint[q] = pick(&mut r, pin.quote_mint);
        let v = PushView {
            market: pick(&mut r, pin.market), asset_index: if num(&mut r, 8) == 0 { 1 } else { pin.asset_index }, market_id: if num(&mut r, 8) == 0 { 1 } else { pin.market_id },
            pool_key: pick(&mut r, pin.pool), pool_owner: pick(&mut r, pin.amm_program),
            sides: PoolSides { mint, vault, token_program: [t0, t1] },
            base_vault_key: pick(&mut r, pin.base_vault), quote_vault_key: pick(&mut r, pin.quote_vault),
            base_vault_program: t0.unwrap_or_else(|| key(&mut r)), quote_vault_program: t1.unwrap_or_else(|| key(&mut r)),
            base_vault: TokenAcct { mint: pick(&mut r, pin.base_mint), amount: 1 },
            quote_vault: TokenAcct { mint: pick(&mut r, pin.quote_mint), amount: 1 },
        };
        let all = pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0
            && pin.market == v.market && pin.asset_index == v.asset_index && pin.market_id == v.market_id
            && v.pool_owner == pin.amm_program && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
            && v.pool_key == pin.pool && v.base_vault_key == pin.base_vault && v.quote_vault_key == pin.quote_vault
            && v.sides.vault[b] == pin.base_vault && v.sides.vault[q] == pin.quote_vault
            && v.sides.mint[b] == pin.base_mint && v.sides.mint[q] == pin.quote_mint
            && v.base_vault.mint == pin.base_mint && v.quote_vault.mint == pin.quote_mint
            && v.sides.token_program[b].map_or(true, |p| p == v.base_vault_program)
            && v.sides.token_program[q].map_or(true, |p| p == v.quote_vault_program);
        let ok = pin_matches(&pin, &v);
        assert_eq!(ok, all);
        n += 1;
        if ok { accepted += 1; }
    }
    println!("pin_matches sweep: n={n} accepted={accepted}");
    assert!(accepted > 10_000);
}
