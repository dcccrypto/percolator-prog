//! SDK parity fixture binary for percolator-prog.
//!
//! Emits the JSON that `percolator-sdk/scripts/check-parity-fixtures.mjs`
//! compares against `percolator-sdk/specs/wrapper-tags.json`.
//!
//!   cargo run --quiet --bin sdk_parity_fixtures
//!
//! #375: this binary did not exist, so the Parity Gate's `percolator-prog` target
//! failed with `cargo run failed` on every run since at least 2026-08-23 — with a
//! second cause on top, since the job did not check out the `percolator` engine
//! this crate depends on by path. ABI drift in the wrapper had NO automated
//! detection at all.
//!
//! ── WHY THIS PROBES `decode` RATHER THAN READING THE SOURCE ──────────────────
//!
//! The obvious implementation is to parse the `match tag` arms. Do not: while
//! writing this fixture, a regex over `N => Self::Variant` reported 69 tags and
//! concluded that `BatchTradeNoCpi`/`BatchTradeCpi` (66/67) did not exist and that
//! the SDK spec had invented them. Both DO exist — they are dispatched in block
//! form (`66 => { ... }`), which the pattern silently skipped. A parser that is
//! wrong about the dispatcher produces a spec that is confidently wrong, which is
//! worse than no gate at all.
//!
//! Asking `Instruction::decode` cannot make that mistake. Every tag byte is probed
//! with candidate payload lengths and we record which variant comes back, so the
//! answer comes from the same code path the runtime uses.
//!
//! The variant NAMES below are the one hand-written part, and deliberately not the
//! part that drifts: the tag->variant binding is discovered at runtime, so
//! renumbering is caught even though the names are spelled out. A renamed variant
//! fails to compile, which is its own alarm.
//!
//! No serde: this crate builds an on-chain program, so the JSON is emitted
//! directly rather than adding a dependency to the program's graph for a dev-only
//! binary.

use percolator_prog::ix::Instruction;

/// Highest tag byte probed. Comfortably above the live range so a tag appended at
/// the tail is picked up without editing this file.
const MAX_TAG: u8 = 127;
/// Payload lengths tried per tag, in bytes.
///
/// This MUST exceed the largest instruction body or a live tag is silently
/// reported as a gap. `InitMarket` is the largest at 218 bytes
/// (1 u16 + 15 u64 + 6 u128), and a first draft of this file capped the probe at
/// 200 and duly reported tag 0 as unallocated. The canary in `main` now makes
/// that specific mistake impossible to ship.
const MAX_PAYLOAD: usize = 512;

/// FOUR NAMES ARE DELIBERATELY THE SDK'S, NOT THE PROGRAM'S.
///
///   tag 3  Deposit             -> "DepositCollateral"
///   tag 4  Withdraw            -> "WithdrawCollateral"
///   tag 5  PermissionlessCrank -> "KeeperCrank"
///   tag 8  ClosePortfolio      -> "CloseAccount"
///
/// These are NOT drift. `DepositCollateral`, `WithdrawCollateral` and
/// `KeeperCrank` have never appeared in this crate's source at any commit; they
/// are the SDK's own vocabulary, declared as such (`@alias DepositCollateral
/// @since v12.x alias` in `src/abi/instructions.ts`) and keyed on by
/// `test/parity-fixtures.test.ts`.
///
/// Emitting the program names here would rename four entries of the SDK's public
/// surface to fix nothing: this gate exists to catch a TAG being renumbered or an
/// instruction appearing/disappearing, and the tag binding below is discovered by
/// probing `decode`, so it is caught either way. Renaming a variant in the program
/// still breaks the build at the match arm.
fn variant_name(ix: &Instruction) -> &'static str {
    match ix {
        Instruction::InitMarket { .. } => "InitMarket",
        Instruction::InitPortfolio { .. } => "InitPortfolio",
        Instruction::Deposit { .. } => "DepositCollateral",
        Instruction::Withdraw { .. } => "WithdrawCollateral",
        Instruction::PermissionlessCrank { .. } => "KeeperCrank",
        Instruction::TradeNoCpi { .. } => "TradeNoCpi",
        Instruction::TradeCpi { .. } => "TradeCpi",
        Instruction::BatchTradeNoCpi { .. } => "BatchTradeNoCpi",
        Instruction::BatchTradeCpi { .. } => "BatchTradeCpi",
        Instruction::SetMatcherConfig { .. } => "SetMatcherConfig",
        Instruction::ClosePortfolio { .. } => "CloseAccount",
        Instruction::TopUpInsurance { .. } => "TopUpInsurance",
        Instruction::TopUpInsuranceDomain { .. } => "TopUpInsuranceDomain",
        Instruction::CloseSlab { .. } => "CloseSlab",
        Instruction::ResolveMarket { .. } => "ResolveMarket",
        Instruction::TopUpBackingBucket { .. } => "TopUpBackingBucket",
        Instruction::WithdrawBackingBucket { .. } => "WithdrawBackingBucket",
        Instruction::ConvertReleasedPnl { .. } => "ConvertReleasedPnl",
        Instruction::CloseResolved { .. } => "CloseResolved",
        Instruction::UpdateAuthority { .. } => "UpdateAuthority",
        Instruction::UpdateAssetAuthority { .. } => "UpdateAssetAuthority",
        Instruction::UpdateLiquidationFeePolicy { .. } => "UpdateLiquidationFeePolicy",
        Instruction::UpdateMaintenanceFeePolicy { .. } => "UpdateMaintenanceFeePolicy",
        Instruction::UpdateBackingFeePolicy { .. } => "UpdateBackingFeePolicy",
        Instruction::UpdateTradeFeePolicy { .. } => "UpdateTradeFeePolicy",
        Instruction::UpdateFeeRedirectPolicy { .. } => "UpdateFeeRedirectPolicy",
        Instruction::UpdateInsuranceWithdrawPolicy { .. } => "UpdateInsuranceWithdrawPolicy",
        Instruction::UpdateMarketInitFeePolicy { .. } => "UpdateMarketInitFeePolicy",
        Instruction::WithdrawBackingBucketEarnings { .. } => "WithdrawBackingBucketEarnings",
        Instruction::SyncBackingDomainLedger { .. } => "SyncBackingDomainLedger",
        Instruction::SyncInsuranceLedger { .. } => "SyncInsuranceLedger",
        Instruction::ConfigurePermissionlessResolve { .. } => "ConfigurePermissionlessResolve",
        Instruction::ResolveStalePermissionless { .. } => "ResolveStalePermissionless",
        Instruction::ConfigureHybridOracle { .. } => "ConfigureHybridOracle",
        Instruction::ConfigureEwmaMark { .. } => "ConfigureEwmaMark",
        Instruction::PushEwmaMark { .. } => "PushEwmaMark",
        Instruction::ConfigureAuthMark { .. } => "ConfigureAuthMark",
        Instruction::PushAuthMark { .. } => "PushAuthMark",
        Instruction::ForceCloseAbandonedAsset { .. } => "ForceCloseAbandonedAsset",
        Instruction::RestartAssetOracle { .. } => "RestartAssetOracle",
        Instruction::UpdateAssetLifecycle { .. } => "UpdateAssetLifecycle",
        Instruction::WithdrawInsurance { .. } => "WithdrawInsurance",
        Instruction::WithdrawInsuranceAsset { .. } => "WithdrawInsuranceAsset",
        Instruction::CureAndCancelClose { .. } => "CureAndCancelClose",
        Instruction::ForfeitRecoveryLeg { .. } => "ForfeitRecoveryLeg",
        Instruction::RebalanceReduce { .. } => "RebalanceReduce",
        Instruction::FinalizeResetSide { .. } => "FinalizeResetSide",
        Instruction::ClaimResolvedPayoutTopup { .. } => "ClaimResolvedPayoutTopup",
        Instruction::RefineResolvedUnreceiptedBound { .. } => "RefineResolvedUnreceiptedBound",
        Instruction::SyncMaintenanceFee { .. } => "SyncMaintenanceFee",
        Instruction::UpdateBaseUnitMints { .. } => "UpdateBaseUnitMints",
        Instruction::SwapSecondaryForPrimary { .. } => "SwapSecondaryForPrimary",
        Instruction::CreateLpVault { .. } => "CreateLpVault",
        Instruction::DepositToLpVault { .. } => "DepositToLpVault",
        Instruction::RebalanceLpVaultBacking { .. } => "RebalanceLpVaultBacking",
        Instruction::RequestRedeemLpShares { .. } => "RequestRedeemLpShares",
        Instruction::ExecuteRedemption { .. } => "ExecuteRedemption",
        Instruction::LpVaultCrankFees { .. } => "LpVaultCrankFees",
        Instruction::SetLpVaultPaused { .. } => "SetLpVaultPaused",
        Instruction::CloseLpVault { .. } => "CloseLpVault",
        Instruction::CancelRedemption { .. } => "CancelRedemption",
        Instruction::TransferPortfolioOwnership { .. } => "TransferPortfolioOwnership",
        Instruction::SetNftProgramId { .. } => "SetNftProgramId",
        Instruction::UnwrapEscrowedPortfolio { .. } => "UnwrapEscrowedPortfolio",
        Instruction::InitMatcherCtx { .. } => "InitMatcherCtx",
        Instruction::WithdrawProtocolFee { .. } => "WithdrawProtocolFee",
        Instruction::SetProtocolFeeAuthority { .. } => "SetProtocolFeeAuthority",
        Instruction::UpdateFeeSplit { .. } => "UpdateFeeSplit",
        Instruction::WithdrawInsuranceReserveToStake { .. } => "WithdrawInsuranceReserveToStake",
        Instruction::UpdateMaintenanceFeePerSlot { .. } => "UpdateMaintenanceFeePerSlot",
        Instruction::ExpireBackingBucket { .. } => "ExpireBackingBucket",
        Instruction::WithdrawCreatorFee { .. } => "WithdrawCreatorFee",
    }
}

fn main() {
    let mut live: Vec<(u8, &'static str)> = Vec::new();
    let mut gaps: Vec<u8> = Vec::new();

    for tag in 0..=MAX_TAG {
        let mut found: Option<&'static str> = None;
        for len in 0..=MAX_PAYLOAD {
            let mut data = vec![0u8; len + 1];
            data[0] = tag;
            if let Ok(ix) = Instruction::decode(&data) {
                found = Some(variant_name(&ix));
                break;
            }
        }
        match found {
            Some(name) => live.push((tag, name)),
            None => gaps.push(tag),
        }
    }

    // Only holes BELOW the highest live tag are GAPS; everything past the tail is
    // unallocated and would otherwise report dozens of meaningless entries.
    let highest_live = live.last().map(|(t, _)| *t).unwrap_or(0);
    gaps.retain(|t| *t < highest_live);

    // ── Proof of life ────────────────────────────────────────────────────────
    // A silent empty emit, or one missing the tags nobody would look twice at,
    // reads as "parity OK" forever.
    assert!(!live.is_empty(), "no live tags decoded — the probe is broken");
    // Tag 0 is InitMarket, the LARGEST instruction body in the program. If
    // MAX_PAYLOAD ever falls below it, this is the first thing that breaks — and
    // it breaks loudly, rather than quietly moving tag 0 into `gaps`.
    assert!(
        live.iter().any(|(t, _)| *t == 0),
        "tag 0 (InitMarket) did not decode — MAX_PAYLOAD ({MAX_PAYLOAD}) is \
         smaller than the largest instruction body"
    );

    let mut out = String::from("{\n  \"gaps\": [\n");
    for (i, tag) in gaps.iter().enumerate() {
        let comma = if i + 1 == gaps.len() { "" } else { "," };
        out.push_str(&format!("    {tag}{comma}\n"));
    }
    out.push_str("  ],\n");
    out.push_str("  \"program\": \"percolator-prog\",\n");
    out.push_str("  \"tags\": [\n");
    for (i, (tag, name)) in live.iter().enumerate() {
        let comma = if i + 1 == live.len() { "" } else { "," };
        // One line per tag, matching the format the committed spec already used.
        // The checker compares the files byte-for-byte, so the emitted shape IS
        // the spec's shape; keeping it means the review diff shows the twelve new
        // instructions rather than 350 lines of reflow.
        out.push_str(&format!(
            "    {{ \"name\": \"{name}\", \"tag\": {tag} }}{comma}\n"
        ));
    }
    out.push_str("  ],\n");
    out.push_str("  \"version\": \"v17\"\n}\n");
    print!("{out}");
}
