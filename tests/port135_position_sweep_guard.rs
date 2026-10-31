//! port135 (upstream 0c5d4f4f, att645 F1/F1b): source-level guard for the instruction-level
//! out-of-matcher position sweep.
//!
//! Upstream invalidates a stale matcher capability at every out-of-matcher position mutation.
//! This fork has many wrapper-side engine Refresh sites (vault-LP draws, Earn / bond flows, rent,
//! backstop, recall, ...) that can clear a side-reset leg. Instead of a wrapper per site, the
//! wrapper snapshots every writable portfolio before the instruction and bumps the episode
//! (invalidating a non-synced matcher) after it, for every instruction except the few that apply
//! their own policy. This test pins that structure so a refactor or a new handler cannot drop it:
//!
//! 1. `process_instruction` runs snapshot -> `dispatch_decoded` -> apply, in that order.
//! 2. The exempt set (`instruction_manages_own_position_policy`) is exactly the pinned list.
//! 3. Each exempt instruction's dispatch arm applies its own policy wrapper.
//! 4. Every direct engine Refresh / liquidation / wind-down call site sits in a pinned set of
//!    functions. A NEW call site fails this test, so its reachability from the exempt set gets
//!    reviewed. Today exactly one pinned site is reachable from exempt arms:
//!    `vault_lp_physical_draw` via `vault_lp_trade_pre_draw` (TradeNoCpi / TradeCpi and the
//!    batch routes, on the vault LP). TradeNoCpi's wrapper invalidates the LP anyway; on TradeCpi
//!    the vault LP is the matcher-fill side, whose in-trade refresh is treated as seen by its
//!    matcher (a documented residual, same as upstream's executor).

const SRC: &str = include_str!("../src/v16_program.rs");

fn fn_body<'a>(src: &'a str, signature_start: &str) -> &'a str {
    let start = src
        .find(signature_start)
        .unwrap_or_else(|| panic!("`{signature_start}` not found"));
    let open = start + src[start..].find('{').expect("body open");
    let mut depth = 0usize;
    for (off, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[start..open + off + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced body for `{signature_start}`")
}

fn code_only(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn port135_process_instruction_sweeps_around_dispatch() {
    let body = code_only(fn_body(SRC, "pub fn process_instruction<'a>("));
    let snap = body.find("out_of_matcher_sweep_snapshot(").expect("snapshot call");
    let disp = body.find("dispatch_decoded(").expect("dispatch_decoded call");
    let apply = body.find("out_of_matcher_sweep_apply(").expect("apply call");
    assert!(snap < disp && disp < apply, "snapshot -> dispatch -> apply order");
    assert!(
        !body.contains("process_instruction_dispatch("),
        "the outer entry must dispatch through dispatch_decoded, inside the sweep"
    );
    // The only other entry into the dispatcher is the nested (exempt) EvictAndTradeCpi trade.
    let nested: Vec<_> = SRC.match_indices("process_instruction_dispatch(program_id").collect();
    assert_eq!(nested.len(), 1, "exactly one nested dispatch (EvictAndTradeCpi's inner TradeCpi)");
}

const EXEMPT: &[&str] = &[
    "TradeNoCpi",
    "TradeCpi",
    "BatchTradeNoCpi",
    "BatchTradeCpi",
    "EvictAndTradeCpi",
    "SweepBandDustLeg",
    "RebalanceReduce",
    "ForfeitRecoveryLeg",
    "LevGuard",
];

#[test]
fn port135_exempt_set_is_pinned() {
    let body = code_only(fn_body(SRC, "fn instruction_manages_own_position_policy("));
    let mut found: Vec<&str> = body
        .match_indices("Instruction::")
        .map(|(i, _)| {
            let rest = &body[i + "Instruction::".len()..];
            let end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap();
            &rest[..end]
        })
        .collect();
    found.sort();
    let mut want = EXEMPT.to_vec();
    want.sort();
    assert_eq!(found, want, "the sweep's exempt set changed: review every new exemption");
    assert!(body.contains("OP_LP_STOP"), "LevGuard is exempt for OP_LP_STOP only");
}

#[test]
fn port135_each_exempt_arm_applies_its_own_policy() {
    let dispatch = code_only(fn_body(SRC, "fn dispatch_decoded<'a>("));
    for name in EXEMPT {
        let pat = format!("Instruction::{name} {{");
        let at = dispatch
            .find(&pat)
            .unwrap_or_else(|| panic!("dispatch arm for {name} not found"));
        // The arm runs up to the next top-level `Instruction::` arm.
        let rest = &dispatch[at + pat.len()..];
        let end = rest.find("\n            Instruction::").unwrap_or(rest.len());
        let arm = &rest[..end];
        assert!(
            arm.contains("with_matcher_invalidations("),
            "{name}: an exempt instruction must invalidate through with_matcher_invalidations"
        );
    }
}

/// Engine entry points that can move a portfolio's position vector outside any matcher
/// (Refresh can clear a side-reset leg; liquidation / wind-down close legs).
const ENGINE_MUTATORS: &[&str] = &[
    ".full_account_refresh_not_atomic(",
    ".full_account_refresh_with_s10_budget_not_atomic(",
    ".permissionless_crank_not_atomic(",
    ".permissionless_crank_s10_not_atomic(",
    ".permissionless_auto_crank_not_atomic(",
    ".permissionless_auto_crank_s10_not_atomic(",
    ".wind_down_adl_position_not_atomic(",
    ".liquidate_account_not_atomic(",
];

/// The functions that hold those calls today (reachability from exempt arms: see the module doc).
const PINNED_SITES: &[&str] = &[
    "bond_value_before_leg",
    "handle_adl_wind_down",
    "handle_convert_released_pnl",
    "handle_insurance_backstop_draw",
    "handle_permissionless_crank_zero_copy",
    "handle_settle_holding_rent",
    "handle_vault_lp_convert_pnl",
    "handle_vault_lp_recall",
    "vault_cover_resolved_claim_shortfall",
    "vault_lp_allocate_core",
    "vault_lp_physical_draw",
];

fn enclosing_fn(src: &str, at: usize) -> String {
    let before = &src[..at];
    let mut best: Option<(usize, String)> = None;
    for (i, _) in before.match_indices("fn ") {
        let prev = before[..i].chars().last();
        if !matches!(prev, Some(' ') | Some('\n')) {
            continue;
        }
        let rest = &before[i + 3..];
        let end = rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(0);
        if end == 0 {
            continue;
        }
        // Only item definitions at 4-space indentation (module members).
        let line_start = before[..i].rfind('\n').map_or(0, |p| p + 1);
        let indent = &before[line_start..i];
        if !indent.trim_start_matches(' ').is_empty()
            && !["pub ", "pub(crate) "].iter().any(|p| indent.trim_start().starts_with(p))
        {
            continue;
        }
        if indent.len() - indent.trim_start().len() != 4 {
            continue;
        }
        best = Some((i, rest[..end].to_string()));
    }
    best.expect("enclosing fn").1
}

#[test]
fn port135_engine_mutator_sites_are_pinned() {
    let mut sites: Vec<String> = Vec::new();
    for pat in ENGINE_MUTATORS {
        for (at, _) in SRC.match_indices(pat) {
            let line_start = SRC[..at].rfind('\n').map_or(0, |p| p + 1);
            let line = &SRC[line_start..at];
            if line.contains("//") {
                continue;
            }
            sites.push(enclosing_fn(SRC, at));
        }
    }
    sites.sort();
    sites.dedup();
    let mut want: Vec<String> = PINNED_SITES.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        sites, want,
        "a direct engine Refresh/liquidation/wind-down call site was added or moved: confirm it is \
         not reachable from an exempt instruction (instruction_manages_own_position_policy), \
         then pin it here"
    );
}
