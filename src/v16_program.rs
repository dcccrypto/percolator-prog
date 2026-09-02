//! Percolator v16 Solana wrapper.
//!
//! v16 is account-local: a market-group account stores `MarketGroupV16`, and
//! each trader/LP is an independently supplied `PortfolioAccountV16`. The
//! wrapper deliberately does not recreate the legacy global account slab.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use percolator::{
    v16_domain_count_for_market_slots, BackingBucketStatusV16, MarketModeV16,
    PermissionlessCrankActionV16, PermissionlessCrankRequestV16, RebalanceRequestV16, SideV16,
    SourceCreditStateV16, TradeRequestV16, V16Config, V16Error, BOUND_SCALE,
};
use solana_program::{
    account_info::AccountInfo,
    bpf_loader_upgradeable,
    clock::Clock,
    declare_id,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction as SolInstruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    system_program,
    sysvar::Sysvar,
};

declare_id!("Perco1ator111111111111111111111111111111111");

pub mod constants {
    use core::mem::size_of;
    use percolator::{
        Market, MarketGroupV16HeaderAccount, PortfolioAccountV16Account,
        PortfolioSourceDomainV16Account,
    };

    pub const MAGIC: u64 = 0x5045_5243_5631_3600; // "PERCV16\0"
    // Protocol-fee program change (taker-only trade fee + 20% protocol skim,
    // see ~/v17/PROTOCOL-FEE-DESIGN.md): WrapperConfigV16 grows 432 -> 496 B
    // (additive at the tail). Bump VERSION so `check_header` fail-closed
    // rejects any pre-existing (old-layout) account rather than misparsing
    // it -- this forces the explicitly-allowed devnet re-seed.
    pub const VERSION: u16 = 17;
    pub const KIND_MARKET: u8 = 1;
    pub const KIND_PORTFOLIO: u8 = 2;
    pub const KIND_BACKING_DOMAIN_LEDGER: u8 = 3;
    pub const KIND_INSURANCE_LEDGER: u8 = 4;

    pub const HEADER_LEN: usize = 16;
    pub const WRAPPER_CONFIG_LEN: usize = 576;
    pub const ASSET_ORACLE_PROFILE_LEN: usize = 400;
    pub const ASSET_ORACLE_WRAPPER_LEN: usize = 512;
    pub const MARKET_GROUP_LEN: usize = size_of::<MarketGroupV16HeaderAccount>();
    pub const MARKET_ASSET_SLOT_LEN: usize = size_of::<Market<[u8; ASSET_ORACLE_WRAPPER_LEN]>>();
    pub const PORTFOLIO_STATE_LEN: usize = size_of::<PortfolioAccountV16Account>();
    pub const PORTFOLIO_SOURCE_DOMAIN_LEN: usize = size_of::<PortfolioSourceDomainV16Account>();
    pub const MARKET_GROUP_OFF: usize = HEADER_LEN + WRAPPER_CONFIG_LEN;
    pub const MIN_MARKET_ACCOUNT_LEN: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN;
    pub const DEFAULT_MARKET_SLOT_CAPACITY: usize = 1;
    pub const MARKET_ACCOUNT_LEN: usize =
        MARKET_GROUP_OFF + MARKET_GROUP_LEN + DEFAULT_MARKET_SLOT_CAPACITY * MARKET_ASSET_SLOT_LEN;
    // Source-domains are a fixed sparse array embedded in PORTFOLIO_STATE_LEN (no 2N tail):
    // the portfolio account is fixed-size, independent of the market asset count N.
    pub const PORTFOLIO_ENGINE_ACCOUNT_LEN: usize = HEADER_LEN + PORTFOLIO_STATE_LEN;
    pub const PORTFOLIO_MATCHER_CONFIG_OFF: usize = PORTFOLIO_ENGINE_ACCOUNT_LEN;
    pub const PORTFOLIO_MATCHER_CONFIG_LEN: usize = 104;
    pub const PORTFOLIO_ACCOUNT_LEN: usize =
        PORTFOLIO_ENGINE_ACCOUNT_LEN + PORTFOLIO_MATCHER_CONFIG_LEN;
    pub const MAX_MATCHER_TAIL_ACCOUNTS: usize = 32;
    pub const MATCHER_ABI_VERSION: u32 = 3;
    pub const MATCHER_CONTEXT_MIN_LEN: usize = 64;
    pub const ORACLE_LEG_CAP: usize = 3;
    pub const ORACLE_MODE_MANUAL: u8 = 0;
    pub const ORACLE_MODE_HYBRID_AFTER_HOURS: u8 = 1;
    pub const ORACLE_MODE_EWMA_MARK: u8 = 2;
    pub const ORACLE_MODE_AUTH_MARK: u8 = 3;
    pub const ORACLE_LEG_FLAG_DIVIDE_LEG2: u8 = 1 << 0;
    pub const ORACLE_LEG_FLAG_DIVIDE_LEG3: u8 = 1 << 1;
    pub const ORACLE_LEG_FLAGS_MASK: u8 = ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3;
    pub const SWITCHBOARD_RESULT_SCALE: u128 = 1_000_000_000_000;
    pub const DEFAULT_MARK_EWMA_HALFLIFE_SLOTS: u64 = 600;
    pub const MAX_DYNAMIC_TRADE_FEE_BPS: u64 = 10_000;
    pub const MAX_PERMISSIONLESS_RESOLVE_STALE_SLOTS: u64 = 6_480_000;
    /// Lower bound for `permissionless_resolve_stale_slots` (#410). ~1 hour at 2.5 slots/s.
    ///
    /// The old validation rejected only `== 0`, so `1` was accepted: a SINGLE missed oracle
    /// refresh could permanently resolve a market, and resolution is one-way. The README
    /// describes this timer as the user-exit path for when an oracle STOPS WORKING — a dead
    /// feed, not a late one.
    ///
    /// An hour must exceed any plausible TRANSIENT (keeper restart, RPC lag, a missed crank)
    /// while still letting a genuinely abandoned market be resolved the same day. There is no
    /// cadence parameter to anchor to: `hybrid_soft_stale_slots` is per-asset while this is
    /// market-level, so a relative bound is not available here.
    ///
    /// Upstream has the identical missing bound — nothing to port, no stricter reference to
    /// defer to. This diverges deliberately.
    pub const MIN_PERMISSIONLESS_RESOLVE_STALE_SLOTS: u64 = 9_000;
    pub const MAX_FORCE_CLOSE_DELAY_SLOTS: u64 = 10_000_000;
    pub const MIN_INSURANCE_WITHDRAW_FLOOR_UNITS: u128 = 10;
    /// Fork B-11 upper bound on per-asset `max_staleness_secs`. v16 baseline
    /// has no upper bound — an operator could configure unbounded oracle
    /// staleness, which loosens the trade / mark / liquidation gates beyond
    /// what fork wants to permit. The 24-hour cap is the fork's audited
    /// envelope (see wrapper_design_B11_oracle_staleness_cap.md). Bound is
    /// enforced at every site that ingests `max_staleness_secs` from
    /// instruction args before storage.
    pub const MAX_ORACLE_STALENESS_SECS: u64 = 86_400;
    // v16 market slots are dynamic and bounded by SVM account allocation, but
    // one portfolio may only carry the largest active-leg count that fits the
    // audited stale-trade and crank CU envelope. Additional markets remain
    // usable through separate portfolios.
    pub const WRAPPER_MAX_PORTFOLIO_ASSETS: u16 = 14;

    // ── Protocol-fee program change ─────────────────────────────────────
    // See ~/v17/PROTOCOL-FEE-DESIGN.md §0/§2. `PROTOCOL_FEE_BPS` is the
    // rate applied via `fee_share_floor` to 100% of every trade-fee credit
    // (the `policy_v16::split_trade_fee` call sites in the single-trade and
    // batch fee post-passes). It is a compile-time constant, never stored on-chain and
    // never settable by anyone short of a program upgrade -- there is
    // deliberately no `SetProtocolFeeBps` instruction (design §3.3).
    pub const PROTOCOL_FEE_BPS: u16 = 2000;
    /// Fee-split defaults (2026-07-19 design). Written unconditionally at
    /// InitMarket, never caller-supplied -- a market that never calls
    /// UpdateFeeSplit still pays all four legs correctly from its first trade.
    pub const DEFAULT_CREATOR_SHARE_BPS: u16 = 1600;
    pub const DEFAULT_LP_SHARE_BPS: u16 = 4800;
    pub const DEFAULT_INSURANCE_SHARE_BPS: u16 = 1600;
    /// The three stored shares must sum to exactly this (= 10_000 - PROTOCOL_FEE_BPS).
    pub const FEE_SHARE_TOTAL_BPS: u16 = 10_000 - PROTOCOL_FEE_BPS;
    /// Decided floors (creator <=45%, LP >=40%, insurance >=15%) are
    /// percentages of the POST-PROTOCOL REMAINDER. Shares are stored as bps of
    /// T summing to FEE_SHARE_TOTAL_BPS (8000), so each floor is `pct * 8000`.
    /// These three sum to exactly 8000, i.e. they are precisely complementary.
    pub const MAX_CREATOR_SHARE_BPS: u16 = 3600; // 45% of the remainder
    pub const MIN_LP_SHARE_BPS: u16 = 3200;      // 40% of the remainder
    pub const MIN_INSURANCE_SHARE_BPS: u16 = 1200; // 15% of the remainder
    /// Hardcoded fallback destination for the protocol's accrued fee share,
    /// set unconditionally at `InitMarket` (never an instruction argument).
    /// Rotatable later only via the upgrade-authority-gated
    /// `SetProtocolFeeAuthority` (tag 85). Pinned to the same creator wallet
    /// currently holding upgrade authority on this program (see
    /// DECISIONS-LEDGER.md "Pinned deployed revisions") -- an operational
    /// placeholder the operator is expected to rotate to a real treasury/
    /// multisig via `SetProtocolFeeAuthority` before or shortly after
    /// mainnet, not a permanent design commitment.
    pub const PROTOCOL_FEE_AUTHORITY_DEFAULT: solana_program::pubkey::Pubkey =
        solana_program::pubkey!("FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7");

    // ── Fork LP Vault (v17 re-expression — tags renumbered 74-80) ──────────
    // Account kinds 1-4 are MARKET / PORTFOLIO / BACKING_DOMAIN_LEDGER /
    // INSURANCE_LEDGER. Fork adds kinds 5/6/7. Toly frozen target has no KIND>4;
    // see CI assert below confirming no future toly KIND collides with 5/6/7.
    pub const KIND_LP_VAULT_REGISTRY: u8 = 5;
    pub const KIND_LP_REDEMPTION: u8 = 6;

    /// PDA seeds: registry = ["lp_vault", market_group]; mint =
    /// ["lp_vault_mint", market_group]; redemption =
    /// ["lp_redemption", registry, redeemer].
    pub const LP_VAULT_REGISTRY_SEED: &[u8] = b"lp_vault";
    pub const LP_VAULT_MINT_SEED: &[u8] = b"lp_vault_mint";
    pub const LP_REDEMPTION_SEED: &[u8] = b"lp_redemption";
    /// LP Vault's backing-domain ledger PDA: ["lp_backing_ledger", market, domain_le].
    pub const LP_BACKING_LEDGER_SEED: &[u8] = b"lp_backing_ledger";
    /// LP Vault's shared redemption-escrow SPL token account PDA:
    /// ["lp_escrow", market]. Owned by the registry PDA.
    pub const LP_ESCROW_SEED: &[u8] = b"lp_escrow";

    pub const LP_VAULT_VERSION: u8 = 1;

    /// Expiry slot stamped on the LP Vault's backing bucket. Permanent until
    /// redeemed; large sentinel to avoid any future `expiry_slot + N` overflow.
    pub const LP_VAULT_BACKING_EXPIRY_SLOT: u64 = u64::MAX / 2;

    /// BUG-2 / N7 hardening: dead-share floor locked at the LP vault's TRUE
    /// genesis deposit (mirrors `percolator-stake::state::MINIMUM_LIQUIDITY`,
    /// same canonical value). `handle_deposit_to_lp_vault` mints
    /// `lp_to_mint - LP_VAULT_MINIMUM_LIQUIDITY` to the depositor but still
    /// bumps `registry.total_lp_shares_outstanding` by the FULL `lp_to_mint`
    /// — the difference is never minted to any account, so it becomes
    /// permanently unredeemable "dead" supply. This is the PRIMARY defense
    /// against the ERC4626-style first-depositor share-inflation attack (the
    /// engine's `lp_vault::LP_VAULT_VIRTUAL_SHARES`/`VIRTUAL_ASSETS` offset is
    /// deliberate defense-in-depth on top of this, not the sole mitigation —
    /// see percolator/src/v16.rs lp_vault module doc).
    pub const LP_VAULT_MINIMUM_LIQUIDITY: u128 = 1_000;

    /// #440: upper bound on `CreateLpVault`'s `redemption_cooldown_slots`.
    ///
    /// ~1 year at ~2.5 slots/sec. DELIBERATELY THE SAME NUMBER as
    /// `percolator-stake::processor::MAX_COOLDOWN_SLOTS` (processor.rs:96), which
    /// exists for the identical failure (#121 there): the field is write-once, it
    /// gates the only instruction that returns principal, and
    /// `lp_vault::lp_redemption_cooldown_elapsed` compares
    /// `current_slot >= request_slot.saturating_add(cooldown)`. The saturation is
    /// correct arithmetic — the defect is that nothing stopped the INPUT reaching a
    /// value at which correct saturation pins the deadline past any slot the chain
    /// will ever reach. `CloseLpVault` cannot unwind it either: it requires
    /// `total_lp_shares_outstanding <= LP_VAULT_MINIMUM_LIQUIDITY` and the only
    /// thing that burns depositor shares is the redemption that is blocked, so
    /// depositors AND the admin are stuck for good.
    ///
    /// Why this exact number rather than a tighter one: the two programs are
    /// operated as one system by the same market operators, both cooldowns are set
    /// by the same admin at creation, and a divergent cap would make "what is a
    /// legal cooldown here?" a per-program question with no principle behind the
    /// difference. ~1 year is already far longer than any cooldown a real vault
    /// would use, so the cap costs no legitimate configuration; its whole job is to
    /// keep the deadline REACHABLE.
    ///
    /// WHERE WE DELIBERATELY DIVERGE FROM THE SIBLING: stake also rejects
    /// `cooldown_slots == 0`, and this does NOT. That rejection is justified there
    /// by a reason that does not exist here — stake has an `UpdateConfig` path which
    /// calls the same validator, so a pool created at 0 could never be raised to a
    /// non-zero value without a window in which it had no cooldown (processor.rs:527).
    /// The wrapper has NO update path for this field at all (one writer, :14621),
    /// so there is no such window, and an immediate-redemption vault is a legitimate
    /// operator choice rather than a half-configured state. Rejecting 0 here would
    /// also be a behaviour change that strands nothing and forbids something the
    /// deployed program has always allowed and that the suite exercises heavily
    /// (`setup_vault(0)` throughout tests/v16_fork_lp_vault_redeem.rs). The bug in
    /// #440 is unbounded ABOVE; that is what is bounded.
    pub const MAX_LP_REDEMPTION_COOLDOWN_SLOTS: u64 = 78_840_000;
    /// Upper bound for `insurance_withdraw_cooldown_slots` (#427). Same magnitude and
    /// same reason as `MAX_LP_REDEMPTION_COOLDOWN_SLOTS`: ~1 year at 2.5 slots/s.
    ///
    /// A setter for a cooldown MUST carry a cap. Adding `UpdateInsuranceWithdrawPolicy`
    /// without one would have closed #427 by opening #440's exact shape — an admin
    /// setting `u64::MAX` and freezing insurance withdrawals forever. The point of the
    /// fix is that the policy becomes REACHABLE, not that it becomes unbounded.
    pub const MAX_INSURANCE_WITHDRAW_COOLDOWN_SLOTS: u64 = 78_840_000;

    /// LP Vault instruction tags (v17 renumbered from 65-71 → 74-80 to avoid
    /// collision with toly's UpdateAssetAuthority(65)/BatchTradeNoCpi(66)/
    /// BatchTradeCpi(67)/SetMatcherConfig(68)/RestartAssetOracle(69)).
    pub const TAG_CREATE_LP_VAULT: u8 = 74;
    pub const TAG_DEPOSIT_TO_LP_VAULT: u8 = 75;
    pub const TAG_REQUEST_REDEEM_LP_SHARES: u8 = 76;
    pub const TAG_EXECUTE_REDEMPTION: u8 = 77;
    pub const TAG_LP_VAULT_CRANK_FEES: u8 = 78;
    pub const TAG_SET_LP_VAULT_PAUSED: u8 = 79;
    pub const TAG_CLOSE_LP_VAULT: u8 = 80;

    // ── Fork NFT / B-3 TransferPortfolioOwnership ─────────────────────────
    // Tags 72/73 are free at the frozen target (toly top=69). NFT-B3 KEPT.
    pub const KIND_NFT_REGISTRY: u8 = 7;

    /// Per-market NFT-program-id registry. PDA seeds: `["nft_registry", market_group]`.
    pub const NFT_REGISTRY_SEED: &[u8] = b"nft_registry";
    pub const NFT_REGISTRY_VERSION: u8 = 1;

    /// SHARED SEED CONTRACT with the percolator-nft program.
    pub const NFT_MINT_AUTHORITY_SEED: &[u8] = b"mint_authority";

    /// B-3 TransferPortfolioOwnership: tag 72.
    /// Wire: tag(72) + new_owner[32] + asset_index(2 LE).
    pub const TAG_TRANSFER_PORTFOLIO_OWNERSHIP: u8 = 72;

    /// SetNftProgramId: tag 73. Wire: tag(73) + nft_program_id[32].
    pub const TAG_SET_NFT_PROGRAM_ID: u8 = 73;

    /// UnwrapEscrowedPortfolio: tag 82. Wire: tag(82) + new_owner[32].
    ///
    /// #105 (escrow-at-mint): the dual of B-3 for the NFT-escrow custody model.
    /// MintPositionNft escrows a position by B-3-transferring `portfolio.owner`
    /// to the NFT program's mint-authority PDA (frozen-while-wrapped); burning
    /// the NFT calls this to release the escrow back to the burning holder.
    ///
    /// Unlike B-3 (tag 72), this is intentionally NOT gated on active-leg /
    /// resolved-payout / liquidation state — an escrowed position may be closed,
    /// liquidated, or resolved while wrapped, and the holder must ALWAYS be able
    /// to reclaim ownership to recover residual collateral or a resolved payout
    /// (else escrow would strand funds). It is instead gated on the escrow
    /// invariant: `portfolio.owner` MUST currently equal the calling NFT
    /// program's mint-authority PDA, so it can only ever release a position this
    /// NFT program escrowed — never seize a normally-owned portfolio. Downstream
    /// owner-gated instructions (Withdraw, CloseResolved, …) retain their own
    /// stale/lock gating, so releasing the owner mid-settlement grants no unsafe
    /// capability.
    pub const TAG_UNWRAP_ESCROWED_PORTFOLIO: u8 = 82;

    // ── SHARED LAYOUT CONTRACT with the percolator-stake program (tag 87) ────
    //
    // `WithdrawInsuranceReserveToStake` pushes the accrued insurance/staker fee
    // leg out of `header.insurance` and into the stake pool's SPL vault, where
    // percolator-stake's `AccrueFees` measures it as surplus over
    // `total_pool_value()` and distributes it to stakers.
    //
    // percolator-prog CANNOT take a Cargo dependency on percolator-stake (the
    // zeroize/solana-2.2 clash documented at
    // `tests/v16_five_program_crosscut.rs:1655`), so the pool is validated by
    // reading raw bytes at pinned offsets — the same technique the crosscut
    // test uses to hand-craft one. These constants mirror
    // `percolator-stake/src/state.rs` (`StakePool`, `STAKE_POOL_SIZE`) and MUST
    // be updated in lockstep with any layout change there.
    // ── PINNED STAKE PROGRAM ID (O1) ────────────────────────────────────────
    // THE STAKE PROGRAM IS PINNED, NOT DISCOVERED. `load_bound_stake_pool`
    // requires `pool_ai.owner == STAKE_PROGRAM_ID` BEFORE it reads a single
    // byte of the account, and derives both PDAs under this constant.
    //
    // This replaces an earlier design that recovered the stake program from
    // `*pool_ai.owner` — i.e. from an account the CALLER supplies — and then
    // validated the pool self-consistently against it. That was forgeable end
    // to end: a market creator deploys program `X`, computes
    // `pool = PDA(["stake_pool", market], X)` and
    // `vault_auth = PDA(["vault_auth", pool], X)`, points asset 0's
    // `insurance_authority` at `vault_auth` (see below), has `X` write a
    // well-formed 392-byte pool with the right discriminator/version/slab/
    // wrapper-id/mode and a `vault` they control, and every check passed —
    // because every check was relative to a program THEY chose. Pinning the id
    // is what makes the rest of the validation mean anything.
    //
    // The old comment justified NOT pinning on the grounds that percolator-stake
    // "has no `declare_id!`" and that candidate ids in this tree disagree
    // (`tests/common/mod.rs::STAKE_ID`, the local keypair, the TS SDK's ids).
    // That was a real problem and it is now fixed at the source:
    // `percolator-stake/src/lib.rs` carries the authoritative `declare_id!`,
    // and this constant mirrors it. The disagreeing ids were stale/local
    // artifacts, not deployments.
    //
    // LINEAGE — verified 2026-07-20 by rebuild-and-compare, NOT taken on trust:
    //   deployed devnet program `GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3`
    //   `solana program dump` -u d, hashed at the ELF's TRUE length (222624 B;
    //   the dump is zero-padded to the allocated length, so a naive sha256 of
    //   the whole buffer is meaningless):
    //     sha256 0e9c25725615c3f11fa4db0cd53a3220f8d7d6f24fc4631bc9975c8970fd6e9c
    //   rebuild of percolator-stake@1e08d35, `cargo build-sbf --features devnet`:
    //     sha256 0e9c25725615c3f11fa4db0cd53a3220f8d7d6f24fc4631bc9975c8970fd6e9c
    //   ⇒ MATCH. GCHhcgw IS percolator-stake@1e08d35.
    //   GOTCHA: the build is PATH-DEPENDENT (root-crate `-C metadata` hash).
    //   Rebuilding at any path other than the canonical `~/v17/percolator-stake`
    //   yields a function-REORDERED ELF (identical `.rodata`, identical section
    //   sizes, different `.text` layout) that will NOT match. Re-verify at the
    //   canonical path or you will chase a phantom mismatch.
    //
    // CLUSTER GATING (mirrors percolator-stake `processor.rs`'s
    // PERCOLATOR_MAINNET/PERCOLATOR_DEVNET allowlist and its N-3 note): the
    // devnet id is behind `#[cfg(feature = "devnet")]` so it cannot compile
    // into a mainnet binary — a compromised devnet deploy keypair must not be
    // able to deploy a malicious binary at that address on mainnet and inherit
    // tag-87 payouts.
    //
    // NO MAINNET ID EXISTS. v17 percolator-stake has no mainnet deployment, and
    // inventing an address would be strictly worse than having none: it would
    // hand tag 87 a destination nobody controls (or worse, one someone else
    // can squat). A default build therefore has NO `STAKE_PROGRAM_ID` at all,
    // and tag 87 FAILS CLOSED at runtime with `StakeProgramNotPinned` — the
    // atoms simply stay in `header.insurance`, which is exactly where they are
    // safe. This is a compile-time-absent / runtime-fail-closed pair rather
    // than a hard `compile_error!`, because the wrapper must still build and
    // deploy for mainnet: tag 87 is one of ~99 instruction tags and the other
    // 98 have no reason to be blocked on a stake deployment that has not
    // happened yet. When stake ships to mainnet, add the mainnet arm HERE and
    // the matching `declare_id!` arm in percolator-stake, in the same change.
    #[cfg(feature = "devnet")]
    pub const STAKE_PROGRAM_ID: solana_program::pubkey::Pubkey =
        solana_program::pubkey!("GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3");

    /// SHARED SEED CONTRACT with percolator-stake: the pool PDA is derived from
    /// the wrapper market it is bound to, so there is exactly ONE pool per
    /// market and the wrapper can compute it rather than trust the caller.
    pub const STAKE_POOL_SEED: &[u8] = b"stake_pool";
    /// SHARED SEED CONTRACT: SPL authority over the pool's vault token account.
    pub const STAKE_VAULT_AUTHORITY_SEED: &[u8] = b"vault_auth";

    /// `percolator-stake::state::STAKE_POOL_SIZE` (v4 — the
    /// `assert!(STAKE_POOL_SIZE == 408)` in that file's const-assert block,
    /// `state.rs:237` at percolator-stake@d0c6ecb, which is `origin/main`).
    /// NOTE: `tests/v16_five_program_crosscut.rs:1662` still crafts the
    /// v2 384-byte shape; that harness is stale, not this constant.
    pub const STAKE_POOL_LEN: usize = 408;
    pub const STAKE_POOL_DISCRIMINATOR: [u8; 8] = *b"SPOOL_V1";
    /// `StakePool::CURRENT_VERSION` (`pub const CURRENT_VERSION: u8 = 4`,
    /// `state.rs:584` at percolator-stake@d0c6ecb = `origin/main`). Checked
    /// EXACTLY, never ignored: the `_reserved` sub-layout has been recarved at
    /// every version bump (352 -> 384 -> 392 -> 408), so a future v5 must fail
    /// loudly here rather than misread `vault` out of a moved field.
    ///
    /// v3 -> v4 (#441) was safe to accept ONLY because it was VERIFIED that every
    /// offset this file reads is unchanged. percolator-stake `state.rs:209-223`
    /// const-asserts `is_initialized@0`, `slab@8`, `vault@136`,
    /// `percolator_program@224`, `pool_mode@280` and `_reserved@320`
    /// (discriminator@320, version@328) — exactly the six constants below. v4's
    /// new fields sit at 288/384/392/400 and disturb none of them. Re-running
    /// that check is the precondition for EVERY future bump. Do not assume it:
    /// the offsets, not the size, are what this file actually depends on.
    ///
    /// v4 is pinned EXCLUSIVELY rather than accepted alongside v3, deliberately.
    /// v3 is the layout whose `_reserved` collision (#242 / PERC-313) silently
    /// disabled the redemption floor and bypassed the cooldown timelock, so
    /// keeping it spendable would keep that defect reachable. The cost is a flag
    /// day: `STAKE_POOL_LEN` is checked with `<`, so a 392-byte v3 pool is now
    /// rejected on length before the version byte is ever read, and every live
    /// pool must be recreated. That is an accepted, deliberate break.
    pub const STAKE_POOL_VERSION: u8 = 4;
    /// Byte offsets into `StakePool` (percolator-stake `state.rs:19-114`).
    pub const STAKE_POOL_OFF_IS_INITIALIZED: usize = 0;
    /// The wrapper market this pool is bound to.
    pub const STAKE_POOL_OFF_SLAB: usize = 8;
    /// The pool's SPL vault token account — the ONLY legal tag-87 destination.
    pub const STAKE_POOL_OFF_VAULT: usize = 136;
    /// The wrapper program this pool CPIs; must equal our own `program_id`.
    pub const STAKE_POOL_OFF_PERCOLATOR_PROGRAM: usize = 224;
    /// 0 = insurance-LP mode (the mode whose stakers absorb losses via
    /// `FlushToInsurance` and are therefore owed this fee leg).
    pub const STAKE_POOL_OFF_MODE: usize = 280;
    pub const STAKE_POOL_MODE_INSURANCE_LP: u8 = 0;
    pub const STAKE_POOL_OFF_DISCRIMINATOR: usize = 320;
    pub const STAKE_POOL_OFF_VERSION: usize = 328;

    // ── Sweep NET-NEW: KIND-byte futures guard ──────────────────────────────
    // Toly's frozen target has no KIND > 4. Our fork KINDs 5/6/7 are safe NOW.
    // This assert fires if a future toly sync introduces KIND_LP_VAULT_REGISTRY=5,
    // KIND_LP_REDEMPTION=6, or KIND_NFT_REGISTRY=7, preventing silent shadowing.
    // check_header() discriminates accounts SOLELY by the KIND byte at offset 10.
    const _ASSERT_KIND_LP_VAULT_REGISTRY_NO_TOLY_COLLISION: () =
        assert!(KIND_LP_VAULT_REGISTRY > KIND_INSURANCE_LEDGER); // 5 > 4
    const _ASSERT_KIND_LP_REDEMPTION_ABOVE: () =
        assert!(KIND_LP_REDEMPTION > KIND_LP_VAULT_REGISTRY); // 6 > 5
    const _ASSERT_KIND_NFT_REGISTRY_ABOVE: () =
        assert!(KIND_NFT_REGISTRY > KIND_LP_REDEMPTION); // 7 > 6
}

pub mod error {
    use percolator::V16Error;
    use solana_program::program_error::ProgramError;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum PercolatorError {
        InvalidMagic,
        InvalidVersion,
        AlreadyInitialized,
        NotInitialized,
        InvalidAccountKind,
        InvalidAccountLen,
        ExpectedSigner,
        ExpectedWritable,
        Unauthorized,
        InvalidInstruction,
        InvalidMint,
        InvalidTokenAccount,
        InvalidVaultAccount,
        InvalidTokenProgram,
        EngineInvalidConfig,
        EngineArithmeticOverflow,
        EngineProvenanceMismatch,
        EngineHiddenLeg,
        EngineInvalidLeg,
        EngineStale,
        EngineBStale,
        EngineLockActive,
        EngineNonProgress,
        EngineRecoveryRequired,
        EngineCounterOverflow,
        EngineCounterUnderflow,
        OracleInvalid,
        OracleStale,
        OracleConfTooWide,
        InvalidOracleKey,
        // ── Fork LP Vault error codes (appended; ordinals 30-41 in enum order) ──
        // INVARIANT: these must remain appended after InvalidOracleKey (ordinal 29).
        // CI test in tests/v16_kani.rs asserts each ordinal. Do NOT reorder.
        LpVaultAlreadyExists,        // Custom(30)
        LpVaultNotFound,             // Custom(31)
        LpVaultPaused,               // Custom(32)
        LpVaultSharesOutstanding,    // Custom(33)
        LpVaultZeroAmount,           // Custom(34)
        LpVaultInsufficientShares,   // Custom(35)
        LpVaultCooldownActive,       // Custom(36)
        LpVaultOiReservationViolated, // Custom(37)
        LpVaultNoFeesToCrank,        // Custom(38)
        LpVaultSupplyMismatch,       // Custom(39)
        LpVaultAuthorityMismatch,    // Custom(40)
        LpVaultZeroSharesMinted,     // Custom(41)
        // ── Fork NFT / B-3 error codes (ordinals 42-46) ─────────────────────
        NftRegistryNotFound,         // Custom(42)
        NftPortfolioNotTransferable, // Custom(43)
        NftTransferSelfOrZero,       // Custom(44)
        NftInvalidMintAuthority,     // Custom(45)
        NftPortfolioProvenance,      // Custom(46)
        // ── Insurance withdrawal policy enforcement (F-1 / F-2) ──────────────
        // Appended after NftPortfolioProvenance (ordinal 46). Do NOT reorder.
        InsuranceWithdrawCooldownActive,  // Custom(47) — F-1: cooldown not elapsed
        InsuranceWithdrawCeilingExceeded, // Custom(48) — F-2: deposits-only ceiling exceeded
        // ── FIX-2: distinct initial-margin failure code ─────────────────────
        // Appended after InsuranceWithdrawCeilingExceeded (ordinal 48). Do NOT reorder.
        /// Equity fell below the initial-margin requirement for the requested action.
        /// Previously collapsed into EngineInvalidConfig (0xe), now surfaced separately
        /// so clients can display "insufficient margin" rather than a generic config error.
        /// SDK agent: add `EngineInsufficientInitialMargin = 49` to the client error map.
        EngineInsufficientInitialMargin,  // Custom(49)
        // ── BUG-2 / N7: LP vault genesis dead-share floor ───────────────────
        // Appended after EngineInsufficientInitialMargin (ordinal 49). Do NOT reorder.
        /// The LP vault's TRUE first deposit (`registry.total_lp_shares_outstanding
        /// == 0` before this call) must exceed `LP_VAULT_MINIMUM_LIQUIDITY` so a
        /// permanent dead-share floor can be locked (N7 anti-inflation hardening,
        /// mirrors percolator-stake's `DepositBelowMinimumLiquidity`). Deposits at
        /// or below the floor are rejected rather than minting 0 (or negative)
        /// real shares to the depositor while still taking their collateral.
        /// SDK agent: add `LpVaultDepositBelowMinimumLiquidity = 50` to the client
        /// error map.
        LpVaultDepositBelowMinimumLiquidity, // Custom(50)
        // ── Fee-split floor enforcement (on-chain mirror of the launch
        // wizard's `feeSplit.ts` floors) ────────────────────────────────
        // Appended after LpVaultDepositBelowMinimumLiquidity (ordinal 50). Do NOT reorder.
        /// `UpdateFeeSplit` (tag 86) shares violate the non-protocol-remainder
        /// floors: `creator > MAX_CREATOR_SHARE_BPS`, `lp < MIN_LP_SHARE_BPS`,
        /// or `insurance < MIN_INSURANCE_SHARE_BPS`. Enforced by
        /// `policy_v16::validate_fee_split`, exactly and with no tolerance.
        ///
        /// HISTORY: this code originally came from `fee_split_floor_ok`, a
        /// tolerance-based check on the two-rate
        /// (`trade_fee_base_bps + backing_fee_bps`) split, raised from
        /// `UpdateBackingFeePolicy` / `UpdateTradeFeePolicy`. That function is
        /// RETIRED and has no live call sites (see its doc comment); the
        /// ordinal is reused rather than vacated because it is wire-visible.
        /// SDK agent: add `FeeSplitFloorViolation = 51` to the client error
        /// map.
        FeeSplitFloorViolation, // Custom(51)
        // ── Fee-collection split (2026-07-19) ───────────────────────────────
        // Appended after FeeSplitFloorViolation (ordinal 51). Do NOT reorder.
        /// `UpdateFeeSplit` shares do not sum to exactly
        /// `FEE_SHARE_TOTAL_BPS` (= 10_000 - PROTOCOL_FEE_BPS).
        /// SDK agent: add `FeeSplitSumInvalid = 52` to the client error map.
        FeeSplitSumInvalid, // Custom(52)
        /// `WithdrawInsuranceReserveToStake` called with nothing available
        /// (`insurance_reserve_accrued == insurance_reserve_withdrawn`).
        /// SDK agent: add `NoInsuranceReserveToClaim = 53` to the client error map.
        NoInsuranceReserveToClaim, // Custom(53)
        // ── `load_bound_stake_pool` diagnostics (2026-07-20) ─────────────────
        // Appended after NoInsuranceReserveToClaim (ordinal 53). Do NOT reorder.
        // These six previously ALL returned `Unauthorized` (Custom 0x…), which
        // left a keeper unable to tell "this market never bound a pool" from
        // "someone pointed a forged pool at us". Each failure now has its own
        // code. SDK agent: add all six to the client error map.
        /// Asset 0's `insurance_authority` is still zero: no stake pool has ever
        /// been bound to this market, so no staker constituency is owed the
        /// insurance leg. Fail closed.
        StakePoolNotBound, // Custom(54)
        /// The supplied stake-pool account is not owned by the pinned
        /// `constants::STAKE_PROGRAM_ID`. THIS IS THE FORGERY GATE: it is
        /// checked before any byte of the account is read, so a pool written by
        /// an attacker-deployed program is rejected outright rather than being
        /// validated self-consistently against that program.
        ///
        /// ORDINAL REUSE (deliberate, ordinals are wire-visible): slot 55 was
        /// `StakePoolAssetAdminNotBurned`, an ineffective mitigation that
        /// required asset 0's `asset_admin` to be burned. It never closed the
        /// forgery — `handle_update_asset_authority`'s self-rotation branch let
        /// the creator (who starts as `insurance_authority` holder via
        /// `InitMarket`) rotate anyway — and it has been removed. That variant
        /// was introduced on this unmerged branch and NEVER deployed
        /// (`6b9c431c` is not an ancestor of the deployed `f6a83370`), so no
        /// on-chain consumer has ever observed Custom(55). Reusing the slot
        /// keeps every neighbouring ordinal (54, 56-59) fixed.
        StakePoolOwnerMismatch, // Custom(55)
        /// `["vault_auth", pool]` derived under the pool account's owning program
        /// does not equal the bound `insurance_authority`. The supplied pool is
        /// not the one that bound itself to this market.
        StakePoolAuthorityMismatch, // Custom(56)
        /// The pool's own stored `slab` does not name this market.
        StakePoolMarketMismatch, // Custom(57)
        /// The pool's stored `percolator_program` (its CPI target) is not this
        /// wrapper deployment.
        StakePoolWrapperMismatch, // Custom(58)
        /// The pool is not in insurance-LP mode (`pool_mode != 0`). Trading-mode
        /// pools carry no `FlushToInsurance` loss exposure, so they are not owed
        /// this leg.
        StakePoolModeMismatch, // Custom(59)
        /// This build has no pinned stake program id, so tag 87 has no
        /// destination it is willing to trust and refuses to move tokens.
        /// Emitted by every non-`devnet` build: v17 percolator-stake has no
        /// mainnet deployment yet (see `constants::STAKE_PROGRAM_ID`). Appended
        /// at the tail so no existing ordinal moves.
        StakeProgramNotPinned, // Custom(60)
        // ── Program bug fixes (2026-07-22) ──────────────────────────────────
        // Appended after StakeProgramNotPinned (ordinal 60). Do NOT reorder.
        /// `UpdateAssetLifecycle(ACTIVATE)` named an asset slot that is BELOW
        /// `max_market_slots` and is already configured and live (lifecycle
        /// Active / DrainOnly / Recovery). Only two activations are legal:
        /// APPEND at `asset_index == max_market_slots`, or RE-ACTIVATE a slot
        /// whose lifecycle is `Retired`. Anything else is a no-op request
        /// against a working slot.
        ///
        /// HISTORY: this previously surfaced as `EngineLockActive` (Custom 21)
        /// — raised either by this wrapper's reuse branch or by the engine's
        /// `activate_empty_market_slot_not_atomic` lifecycle match arm — which
        /// reads as "the market/asset is locked" and gave a caller no hint that
        /// the slot is simply *already in service*. `InitMarket` pre-configures
        /// slots `0..max_portfolio_assets`, so every one of them hits this on a
        /// market created with `max_portfolio_assets > 1`.
        /// SDK agent: add `AssetSlotAlreadyConfigured = 61` to the client error map.
        AssetSlotAlreadyConfigured, // Custom(61)
        // ── Creator fee claim (2026-07-24) ──────────────────────────────────
        // Appended after AssetSlotAlreadyConfigured (ordinal 61). Do NOT reorder.
        /// `WithdrawCreatorFee` (tag 90) asked for more atoms than
        /// `WrapperConfigV16::creator_fee_claimable_atoms` currently holds.
        /// This is a CALLER error (ask for less, or trade more first), not an
        /// internal-invariant violation.
        ///
        /// HISTORY: this capacity rejection originally returned
        /// `EngineCounterUnderflow` (Custom 25) — the code the engine raises
        /// when one of ITS OWN ledgers would go negative, i.e. a "this program
        /// is broken" signal. A creator typing one atom too many is not that,
        /// and collapsing the two left a client unable to distinguish "you
        /// over-asked" from "the market's accounting is corrupt".
        /// `EngineCounterUnderflow` is DELIBERATELY still used for the
        /// handler's own `checked_sub` fail-closed guard, which is unreachable
        /// behind this check and would genuinely mean an internal invariant
        /// broke.
        /// SDK agent: add `CreatorFeeOverClaim = 62` to the client error map.
        CreatorFeeOverClaim, // Custom(62)
        /// CreateLpVault targeted a domain whose backing bucket is ALREADY funded at an
        /// expiry that is not `LP_VAULT_BACKING_EXPIRY_SLOT`.
        ///
        /// Range was checked and reachability was not — the same omission as #440. The vault
        /// would be created, `backing_bucket_authority` taken by the registry PDA, and then:
        /// DepositToLpVault refuses for the whole term because the bucket's expiry does not
        /// match the sentinel, and the provider who funded that bucket can no longer withdraw
        /// because the authority is gone. The only exit is CloseLpVault, which permanently
        /// forfeits the market's ability to ever have an LP vault.
        ///
        /// APPENDED at the end on purpose: adding a variant anywhere else shifts every
        /// ordinal after it, silently re-mapping errors for every deployed client.
        /// SDK agent: add `LpVaultBackingBucketNotEmpty = 63` to the client error map.
        LpVaultBackingBucketNotEmpty, // Custom(63)
    }

    impl From<PercolatorError> for ProgramError {
        fn from(value: PercolatorError) -> Self {
            ProgramError::Custom(value as u32)
        }
    }

    pub fn map_v16_error(err: V16Error) -> ProgramError {
        let mapped = match err {
            V16Error::InvalidConfig => PercolatorError::EngineInvalidConfig,
            V16Error::ArithmeticOverflow => PercolatorError::EngineArithmeticOverflow,
            V16Error::ProvenanceMismatch => PercolatorError::EngineProvenanceMismatch,
            V16Error::HiddenLeg => PercolatorError::EngineHiddenLeg,
            V16Error::InvalidLeg => PercolatorError::EngineInvalidLeg,
            V16Error::Stale => PercolatorError::EngineStale,
            V16Error::BStale => PercolatorError::EngineBStale,
            V16Error::LockActive => PercolatorError::EngineLockActive,
            V16Error::NonProgress => PercolatorError::EngineNonProgress,
            V16Error::RecoveryRequired => PercolatorError::EngineRecoveryRequired,
            V16Error::CounterOverflow => PercolatorError::EngineCounterOverflow,
            V16Error::CounterUnderflow => PercolatorError::EngineCounterUnderflow,
            V16Error::InsufficientInitialMargin => {
                PercolatorError::EngineInsufficientInitialMargin
            }
            // percolator#150 moved the zero-share deposit reject OUT of the wrapper and
            // INTO `lp_vault::lp_shares_for_deposit`, so the engine can now raise this
            // directly. It maps onto the Custom(41) the wrapper already raises at :14974
            // and :16373, so the on-chain error code is unchanged whichever layer rejects.
            //
            // This match is EXHAUSTIVE, which is the point: adding a V16Error variant
            // upstream breaks this build until the arm exists. That is a feature — it is
            // the only thing coupling the two repos at compile time. The engine's own CI
            // was green with this variant added and the wrapper unbuildable.
            V16Error::LpVaultZeroSharesMinted => PercolatorError::LpVaultZeroSharesMinted,
        };
        mapped.into()
    }
}

pub mod state {
    use crate::{
        constants::{
            ASSET_ORACLE_PROFILE_LEN, ASSET_ORACLE_WRAPPER_LEN, HEADER_LEN,
            KIND_BACKING_DOMAIN_LEDGER, KIND_INSURANCE_LEDGER, KIND_MARKET, KIND_PORTFOLIO, MAGIC,
            MARKET_GROUP_LEN, MARKET_GROUP_OFF, MIN_MARKET_ACCOUNT_LEN, ORACLE_LEG_CAP,
            ORACLE_LEG_FLAGS_MASK, ORACLE_MODE_AUTH_MARK, ORACLE_MODE_EWMA_MARK,
            ORACLE_MODE_HYBRID_AFTER_HOURS, ORACLE_MODE_MANUAL, PORTFOLIO_ACCOUNT_LEN,
            PORTFOLIO_ENGINE_ACCOUNT_LEN, PORTFOLIO_MATCHER_CONFIG_LEN,
            PORTFOLIO_MATCHER_CONFIG_OFF, PORTFOLIO_STATE_LEN, VERSION, WRAPPER_CONFIG_LEN,
        },
        error::PercolatorError,
    };
    #[cfg(not(target_os = "solana"))]
    use alloc::boxed::Box;
    #[cfg(not(target_os = "solana"))]
    use alloc::vec::Vec;
    #[cfg(not(target_os = "solana"))]
    use percolator::v16_domain_pair_for_asset_index;
    #[cfg(not(target_os = "solana"))]
    use percolator::{
        v16_domain_count_for_market_slots, BackingBucketV16, CloseProgressLedgerV16, HealthCertV16,
        InsuranceCreditReservationV16, PermissionlessRecoveryReasonV16, PortfolioLegV16,
        PortfolioSourceDomainV16Account, ResolvedPayoutLedgerV16, ResolvedPayoutReceiptV16,
        SourceCreditStateV16, V16ActiveBitmap, V16_MAX_PORTFOLIO_ASSETS_N,
    };
    use percolator::{
        AssetStateV16, EngineAssetSlotV16Account, Market, MarketGroupV16HeaderAccount,
        MarketGroupV16ViewMut, MarketModeV16, PortfolioAccountV16Account, PortfolioV16ViewMut,
        ProvenanceHeaderV16, V16Config, V16Error, V16PodU64,
    };
    use solana_program::program_error::ProgramError;

    #[cfg(not(target_os = "solana"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PortfolioAccountV16 {
        pub provenance_header: ProvenanceHeaderV16,
        pub owner: [u8; 32],
        pub capital: u128,
        pub pnl: i128,
        pub reserved_pnl: u128,
        pub residual_crystallized_loss_atoms_total: u128,
        pub residual_spent_principal_atoms_total: u128,
        pub residual_received_atoms_total: u128,
        pub source_claim_market_id: Vec<u64>,
        pub source_claim_bound_num: Vec<u128>,
        pub source_claim_liened_num: Vec<u128>,
        pub source_claim_counterparty_liened_num: Vec<u128>,
        pub source_claim_insurance_liened_num: Vec<u128>,
        pub source_lien_effective_reserved: Vec<u128>,
        pub source_lien_counterparty_backing_num: Vec<u128>,
        pub source_lien_insurance_backing_num: Vec<u128>,
        pub source_lien_fee_last_slot: Vec<u64>,
        pub source_claim_impaired_num: Vec<u128>,
        pub source_lien_impaired_effective_reserved: Vec<u128>,
        pub source_lien_capital_at_risk_fee_revenue: Vec<u128>,
        pub source_lien_impaired_capital_at_risk_fee_revenue: Vec<u128>,
        pub fee_credits: i128,
        pub cancel_deposit_escrow: u128,
        pub last_fee_slot: u64,
        pub active_bitmap: V16ActiveBitmap,
        pub legs: [PortfolioLegV16; V16_MAX_PORTFOLIO_ASSETS_N],
        pub health_cert: HealthCertV16,
        pub stale_state: bool,
        pub b_stale_state: bool,
        pub rebalance_lock: bool,
        pub liquidation_lock: bool,
        pub close_progress: CloseProgressLedgerV16,
        pub resolved_payout_receipt: ResolvedPayoutReceiptV16,
    }

    #[cfg(not(target_os = "solana"))]
    impl PortfolioAccountV16 {
        fn source_domain_capacity(&self) -> usize {
            self.source_claim_market_id
                .len()
                .min(self.source_claim_bound_num.len())
                .min(self.source_claim_liened_num.len())
                .min(self.source_claim_counterparty_liened_num.len())
                .min(self.source_claim_insurance_liened_num.len())
                .min(self.source_lien_effective_reserved.len())
                .min(self.source_lien_counterparty_backing_num.len())
                .min(self.source_lien_insurance_backing_num.len())
                .min(self.source_lien_fee_last_slot.len())
                .min(self.source_claim_impaired_num.len())
                .min(self.source_lien_impaired_effective_reserved.len())
                .min(self.source_lien_capital_at_risk_fee_revenue.len())
                .min(self.source_lien_impaired_capital_at_risk_fee_revenue.len())
        }

        fn ensure_source_domain_capacity(&mut self, domain_count: usize) {
            self.source_claim_market_id.resize(domain_count, 0);
            self.source_claim_bound_num.resize(domain_count, 0);
            self.source_claim_liened_num.resize(domain_count, 0);
            self.source_claim_counterparty_liened_num
                .resize(domain_count, 0);
            self.source_claim_insurance_liened_num
                .resize(domain_count, 0);
            self.source_lien_effective_reserved.resize(domain_count, 0);
            self.source_lien_counterparty_backing_num
                .resize(domain_count, 0);
            self.source_lien_insurance_backing_num
                .resize(domain_count, 0);
            self.source_lien_fee_last_slot.resize(domain_count, 0);
            self.source_claim_impaired_num.resize(domain_count, 0);
            self.source_lien_impaired_effective_reserved
                .resize(domain_count, 0);
            self.source_lien_capital_at_risk_fee_revenue
                .resize(domain_count, 0);
            self.source_lien_impaired_capital_at_risk_fee_revenue
                .resize(domain_count, 0);
        }
    }

    #[cfg(not(target_os = "solana"))]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct MarketGroupV16 {
        pub market_group_id: [u8; 32],
        pub config: V16Config,
        pub vault: u128,
        pub insurance: u128,
        pub c_tot: u128,
        pub pnl_pos_tot: u128,
        pub pnl_pos_bound_tot_num: u128,
        pub pnl_pos_bound_tot: u128,
        pub pnl_matured_pos_tot: u128,
        // O(1)-in-N market aggregate totals (engine-maintained; mirrored here for host serialization).
        pub backing_provider_earnings_total: u128,
        pub source_claim_bound_total_num: u128,
        // Added v17: backing-principal lifecycle — fresh reserved backing aggregate.
        // Mirrors MarketGroupV16HeaderAccount::source_fresh_backing_total_num (+16B in header ABI).
        pub source_fresh_backing_total_num: u128,
        pub source_insurance_credit_reserved_total_atoms: u128,
        pub insurance_domain_budget_remaining_total: u128,
        pub resolved_payout_blocker_count: u64,
        pub insurance_domain_budget: Vec<u128>,
        pub insurance_domain_spent: Vec<u128>,
        pub pending_domain_loss_barriers: Vec<u64>,
        pub source_credit: Vec<SourceCreditStateV16>,
        pub source_backing_buckets: Vec<BackingBucketV16>,
        pub insurance_credit_reservations: Vec<InsuranceCreditReservationV16>,
        pub materialized_portfolio_count: u64,
        pub stale_certificate_count: u64,
        pub b_stale_account_count: u64,
        pub negative_pnl_account_count: u64,
        pub risk_epoch: u64,
        pub asset_set_epoch: u64,
        pub asset_activation_count: u64,
        pub last_asset_activation_slot: u64,
        pub next_market_id: u64,
        pub oracle_epoch: u64,
        pub funding_epoch: u64,
        pub slot_last: u64,
        pub current_slot: u64,
        pub assets: Vec<AssetStateV16>,
        pub bankruptcy_hlock_active: bool,
        pub threshold_stress_active: bool,
        pub loss_stale_active: bool,
        pub recovery_reason: Option<PermissionlessRecoveryReasonV16>,
        pub mode: MarketModeV16,
        pub resolved_slot: u64,
        pub payout_snapshot: u128,
        pub payout_snapshot_pnl_pos_tot: u128,
        pub payout_snapshot_captured: bool,
        pub resolved_payout_ledger: ResolvedPayoutLedgerV16,
    }

    #[cfg(not(target_os = "solana"))]
    impl MarketGroupV16 {
        pub fn new(market_group_id: [u8; 32], config: V16Config) -> Result<Self, V16Error> {
            config.validate_public_user_fund()?;
            let asset_count = config.max_market_slots as usize;
            let domain_count = v16_domain_count_for_market_slots(config.max_market_slots)?;
            let mut assets = Vec::with_capacity(asset_count);
            let mut source_backing_buckets = Vec::with_capacity(domain_count);
            let mut d = 0usize;
            while d < domain_count {
                source_backing_buckets.push(BackingBucketV16::EMPTY);
                d += 1;
            }
            let mut i = 0usize;
            while i < asset_count {
                let mut asset = AssetStateV16::default();
                asset.market_id = (i as u64).checked_add(1).ok_or(V16Error::CounterOverflow)?;
                assets.push(asset);
                let (long_domain, short_domain) = v16_domain_pair_for_asset_index(i)?;
                source_backing_buckets[long_domain] =
                    BackingBucketV16::empty_for_market(asset.market_id);
                source_backing_buckets[short_domain] =
                    BackingBucketV16::empty_for_market(asset.market_id);
                i += 1;
            }
            let next_market_id = (asset_count as u64)
                .checked_add(1)
                .ok_or(V16Error::CounterOverflow)?;
            Ok(Self {
                market_group_id,
                config,
                vault: 0,
                insurance: 0,
                c_tot: 0,
                pnl_pos_tot: 0,
                pnl_pos_bound_tot_num: 0,
                pnl_pos_bound_tot: 0,
                pnl_matured_pos_tot: 0,
                backing_provider_earnings_total: 0,
                source_claim_bound_total_num: 0,
                source_fresh_backing_total_num: 0,
                source_insurance_credit_reserved_total_atoms: 0,
                insurance_domain_budget_remaining_total: 0,
                resolved_payout_blocker_count: 0,
                insurance_domain_budget: vec_with_value(domain_count, 0u128),
                insurance_domain_spent: vec_with_value(domain_count, 0u128),
                pending_domain_loss_barriers: vec_with_value(domain_count, 0u64),
                source_credit: vec_with_value(domain_count, SourceCreditStateV16::EMPTY),
                source_backing_buckets,
                insurance_credit_reservations: vec_with_value(
                    domain_count,
                    InsuranceCreditReservationV16::EMPTY,
                ),
                materialized_portfolio_count: 0,
                stale_certificate_count: 0,
                b_stale_account_count: 0,
                negative_pnl_account_count: 0,
                risk_epoch: 0,
                asset_set_epoch: 0,
                asset_activation_count: 0,
                last_asset_activation_slot: 0,
                next_market_id,
                oracle_epoch: 0,
                funding_epoch: 0,
                slot_last: 0,
                current_slot: 0,
                assets,
                bankruptcy_hlock_active: false,
                threshold_stress_active: false,
                loss_stale_active: false,
                recovery_reason: None,
                mode: MarketModeV16::Live,
                resolved_slot: 0,
                payout_snapshot: 0,
                payout_snapshot_pnl_pos_tot: 0,
                payout_snapshot_captured: false,
                resolved_payout_ledger: ResolvedPayoutLedgerV16::EMPTY,
            })
        }

        pub fn validate_account_shape(
            &self,
            account: &PortfolioAccountV16,
        ) -> Result<(), V16Error> {
            if account.provenance_header.market_group_id != self.market_group_id
                || account.provenance_header.owner != account.owner
            {
                return Err(V16Error::ProvenanceMismatch);
            }
            if account.source_domain_capacity()
                < v16_domain_count_for_market_slots(self.config.max_market_slots)?
            {
                return Err(V16Error::InvalidLeg);
            }
            let active_leg_cap = self.config.max_portfolio_assets as usize;
            let configured_assets = self.config.max_market_slots as usize;
            let mut seen = vec_with_value(configured_assets, false);
            let mut slot = 0usize;
            while slot < V16_MAX_PORTFOLIO_ASSETS_N {
                let bit = percolator::active_bitmap_get(account.active_bitmap, slot);
                let leg = account.legs[slot];
                if slot >= active_leg_cap {
                    if bit || !leg.is_empty() {
                        return Err(V16Error::HiddenLeg);
                    }
                } else if bit != leg.active {
                    return Err(V16Error::HiddenLeg);
                } else if leg.active {
                    let asset_index = leg.asset_index as usize;
                    if asset_index >= configured_assets || seen[asset_index] {
                        return Err(V16Error::HiddenLeg);
                    }
                    seen[asset_index] = true;
                    if leg.market_id != self.assets[asset_index].market_id {
                        return Err(V16Error::HiddenLeg);
                    }
                } else if !leg.is_empty() {
                    return Err(V16Error::HiddenLeg);
                }
                slot += 1;
            }
            Ok(())
        }

        pub fn add_account_source_positive_pnl_not_atomic(
            &mut self,
            account: &mut PortfolioAccountV16,
            domain: usize,
            amount: u128,
        ) -> Result<(), V16Error> {
            let domain_count = v16_domain_count_for_market_slots(self.config.max_market_slots)?;
            if domain >= domain_count {
                return Err(V16Error::InvalidLeg);
            }
            account.ensure_source_domain_capacity(domain_count);
            self.validate_account_shape(account)?;
            if amount == 0 {
                return Ok(());
            }
            let delta = i128::try_from(amount).map_err(|_| V16Error::ArithmeticOverflow)?;
            let old_pos = account.pnl.max(0) as u128;
            let new_pnl = account
                .pnl
                .checked_add(delta)
                .ok_or(V16Error::ArithmeticOverflow)?;
            let new_pos = new_pnl.max(0) as u128;
            let increase = new_pos
                .checked_sub(old_pos)
                .ok_or(V16Error::CounterUnderflow)?;
            let increase_num = increase
                .checked_mul(percolator::BOUND_SCALE)
                .ok_or(V16Error::ArithmeticOverflow)?;
            if increase_num != 0 {
                let source = &mut account.source_claim_market_id[domain];
                if *source == 0 {
                    let asset_index = domain / 2;
                    if asset_index >= self.assets.len() {
                        return Err(V16Error::InvalidLeg);
                    }
                    *source = self.assets[asset_index].market_id;
                }
                account.source_claim_bound_num[domain] = account.source_claim_bound_num[domain]
                    .checked_add(increase_num)
                    .ok_or(V16Error::CounterOverflow)?;
                let source_credit = self
                    .source_credit
                    .get_mut(domain)
                    .ok_or(V16Error::InvalidLeg)?;
                source_credit.positive_claim_bound_num = source_credit
                    .positive_claim_bound_num
                    .checked_add(increase_num)
                    .ok_or(V16Error::CounterOverflow)?;
                source_credit.exact_positive_claim_num = source_credit
                    .exact_positive_claim_num
                    .checked_add(increase_num)
                    .ok_or(V16Error::CounterOverflow)?;
                recompute_source_credit_rate(source_credit)?;
                self.pnl_pos_tot = self
                    .pnl_pos_tot
                    .checked_add(increase)
                    .ok_or(V16Error::CounterOverflow)?;
                self.pnl_pos_bound_tot_num = self
                    .pnl_pos_bound_tot_num
                    .checked_add(increase_num)
                    .ok_or(V16Error::CounterOverflow)?;
                self.pnl_pos_bound_tot = self.pnl_pos_bound_tot_num / percolator::BOUND_SCALE;
                self.risk_epoch = self
                    .risk_epoch
                    .checked_add(1)
                    .ok_or(V16Error::CounterOverflow)?;
            }
            account.pnl = new_pnl;
            account.health_cert.valid = false;
            Ok(())
        }

        pub fn accrue_asset_to_not_atomic(
            &mut self,
            asset_index: usize,
            now_slot: u64,
            effective_price: u64,
            funding_rate_e9: i128,
            _protective_progress_committed: bool,
        ) -> Result<percolator::AccrueAssetOutcomeV16, V16Error> {
            if self.mode != MarketModeV16::Live
                || asset_index >= self.config.max_market_slots as usize
                || asset_index >= self.assets.len()
                || effective_price == 0
                || now_slot < self.current_slot
            {
                return Err(V16Error::InvalidConfig);
            }
            let old = self.assets[asset_index];
            if now_slot < old.slot_last {
                return Err(V16Error::InvalidConfig);
            }
            let dt_total = now_slot - old.slot_last;
            let segment_dt = dt_total.min(self.config.max_accrual_dt_slots);
            let exposed = old.oi_eff_long_q != 0 || old.oi_eff_short_q != 0;
            let balanced = old.oi_eff_long_q != 0 && old.oi_eff_short_q != 0;
            let price_move_active = effective_price != old.effective_price && exposed;
            let funding_active =
                segment_dt != 0 && funding_rate_e9 != 0 && balanced && old.fund_px_last > 0;
            let price_delta = effective_price as i128 - old.effective_price as i128;
            let k_delta = price_delta
                .checked_mul(percolator::ADL_ONE as i128)
                .ok_or(V16Error::ArithmeticOverflow)?;
            let funding_delta = if funding_active {
                funding_rate_e9
                    .checked_mul(segment_dt as i128)
                    .and_then(|v| v.checked_mul(effective_price as i128))
                    .map(|v| v / percolator::FUNDING_DEN as i128)
                    .and_then(|v| v.checked_mul(percolator::ADL_ONE as i128))
                    .ok_or(V16Error::ArithmeticOverflow)?
            } else {
                0
            };
            let mut asset = old;
            asset.k_long = asset
                .k_long
                .checked_add(k_delta)
                .ok_or(V16Error::ArithmeticOverflow)?;
            asset.k_short = asset
                .k_short
                .checked_sub(k_delta)
                .ok_or(V16Error::ArithmeticOverflow)?;
            asset.f_long_num = asset
                .f_long_num
                .checked_sub(funding_delta)
                .ok_or(V16Error::ArithmeticOverflow)?;
            asset.f_short_num = asset
                .f_short_num
                .checked_add(funding_delta)
                .ok_or(V16Error::ArithmeticOverflow)?;
            asset.effective_price = effective_price;
            asset.fund_px_last = effective_price;
            asset.slot_last = asset
                .slot_last
                .checked_add(segment_dt)
                .ok_or(V16Error::ArithmeticOverflow)?;
            self.assets[asset_index] = asset;
            self.current_slot = now_slot;
            self.slot_last = self
                .assets
                .iter()
                .filter(|asset| {
                    matches!(
                        asset.lifecycle,
                        percolator::AssetLifecycleV16::Active
                            | percolator::AssetLifecycleV16::DrainOnly
                    )
                })
                .map(|asset| asset.slot_last)
                .min()
                .unwrap_or(now_slot);
            if price_move_active {
                self.oracle_epoch = self
                    .oracle_epoch
                    .checked_add(1)
                    .ok_or(V16Error::CounterOverflow)?;
            }
            if funding_active {
                self.funding_epoch = self
                    .funding_epoch
                    .checked_add(1)
                    .ok_or(V16Error::CounterOverflow)?;
            }
            Ok(percolator::AccrueAssetOutcomeV16 {
                dt: segment_dt,
                price_move_active,
                funding_active,
                equity_active: price_move_active || funding_active,
                loss_stale_after: asset.slot_last < now_slot,
            })
        }
    }

    #[cfg(not(target_os = "solana"))]
    fn vec_with_value<T: Clone>(len: usize, value: T) -> Vec<T> {
        let mut out = Vec::with_capacity(len);
        let mut i = 0usize;
        while i < len {
            out.push(value.clone());
            i += 1;
        }
        out
    }

    #[cfg(not(target_os = "solana"))]
    fn recompute_source_credit_rate(source: &mut SourceCreditStateV16) -> Result<(), V16Error> {
        let backing_unliened = source
            .fresh_reserved_backing_num
            .checked_sub(source.valid_liened_backing_num)
            .ok_or(V16Error::InvalidConfig)?;
        let insurance_encumbered = source
            .valid_liened_insurance_num
            .checked_add(source.impaired_liened_insurance_num)
            .ok_or(V16Error::ArithmeticOverflow)?;
        let insurance_available = source
            .insurance_credit_reserved_num
            .checked_sub(insurance_encumbered)
            .ok_or(V16Error::InvalidConfig)?;
        let available = backing_unliened
            .checked_add(insurance_available)
            .ok_or(V16Error::ArithmeticOverflow)?;
        source.credit_rate_num = if source.positive_claim_bound_num == 0 {
            percolator::CREDIT_RATE_SCALE
        } else {
            available
                .checked_mul(percolator::CREDIT_RATE_SCALE)
                .ok_or(V16Error::ArithmeticOverflow)?
                .checked_div(source.positive_claim_bound_num)
                .ok_or(V16Error::ArithmeticOverflow)?
                .min(percolator::CREDIT_RATE_SCALE)
        };
        source.credit_epoch = source
            .credit_epoch
            .checked_add(1)
            .ok_or(V16Error::CounterOverflow)?;
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    fn encode_bool_for_account(value: bool) -> u8 {
        if value {
            1
        } else {
            0
        }
    }

    #[cfg(not(target_os = "solana"))]
    fn encode_market_mode_for_account(value: MarketModeV16) -> u8 {
        match value {
            MarketModeV16::Live => 0,
            MarketModeV16::Resolved => 1,
            MarketModeV16::Recovery => 2,
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct WrapperConfigV16 {
        /// Single market-level authority key. Set to the init signer at InitMarket. Can: create
        /// market 0, activate/retire assets + set the permissionless-create-fee policy, force-shutdown
        /// assets 0..N (RECOVERY with exit window), ResolveMarket / CloseSlab,
        /// market-policy updates, and base-unit mint rotation/swap. Rotated/burned via
        /// UpdateAuthority (tag 32). Replaces the former separate admin / asset_authority /
        /// base_unit_authority keys (which were always the same init signer).
        pub marketauth: [u8; 32],
        pub collateral_mint: [u8; 32],
        pub secondary_collateral_mint: [u8; 32],
        pub maintenance_fee_per_slot: u128,
        pub permissionless_market_init_fee: u128,
        pub trade_fee_base_bps: u64,
        pub permissionless_resolve_stale_slots: u64,
        pub force_close_delay_slots: u64,
        pub last_good_oracle_slot: u64,
        pub insurance_withdraw_deposit_remaining: u128,
        pub insurance_withdraw_max_bps: u16,
        pub liquidation_cranker_fee_share_bps: u16,
        pub maintenance_cranker_fee_share_bps: u16,
        pub backing_trade_fee_bps_long: u16,
        pub unit_scale: u32,
        pub conf_filter_bps: u16,
        pub backing_trade_fee_bps_short: u16,
        pub insurance_withdraw_deposits_only: u8,
        pub oracle_mode: u8,
        pub oracle_leg_count: u8,
        pub oracle_leg_flags: u8,
        pub invert: u8,
        pub _padding0: u8,
        pub free_market_slot_count: u16,
        pub insurance_withdraw_cooldown_slots: u64,
        pub last_insurance_withdraw_slot: u64,
        pub max_staleness_secs: u64,
        pub hybrid_soft_stale_slots: u64,
        pub mark_ewma_e6: u64,
        pub mark_ewma_last_slot: u64,
        pub mark_ewma_halflife_slots: u64,
        pub mark_min_fee: u64,
        pub oracle_target_price_e6: u64,
        pub oracle_target_publish_time: i64,
        pub oracle_leg_feeds: [[u8; 32]; ORACLE_LEG_CAP],
        pub oracle_leg_prices_e6: [u64; ORACLE_LEG_CAP],
        pub oracle_leg_publish_times: [i64; ORACLE_LEG_CAP],
        pub backing_trade_fee_policy_count: u16,
        pub backing_trade_fee_insurance_share_bps_long: u16,
        pub backing_trade_fee_insurance_share_bps_short: u16,
        pub fee_redirect_to_market_0_bps: u16,
        // --- Protocol-fee program change (additive at the tail, 432 -> 496 B; see
        // ~/v17/PROTOCOL-FEE-DESIGN.md §1.4/§2). The 20% protocol skim RATE itself
        // (`PROTOCOL_FEE_BPS`) is a compile-time Rust constant, NOT a field here --
        // it is never stored on-chain and never settable by anyone short of a
        // program upgrade. ---
        /// Destination pubkey for the protocol's accrued fee share. Set to the
        /// hardcoded `PROTOCOL_FEE_AUTHORITY_DEFAULT` at InitMarket (never an
        /// instruction argument, so no market can be created with a
        /// zero/attacker-controlled value here); rotatable only via the
        /// upgrade-authority-gated `SetProtocolFeeAuthority` (tag 85). NOT
        /// settable by `marketauth`/`insurance_authority`/any creator-facing gate.
        pub protocol_fee_authority: [u8; 32],
        /// Cumulative atoms ever accrued to the protocol's claim (monotonic,
        /// only incremented at the two trade-fee credit sites). This value is
        /// never itself credited into any domain's `insurance_domain_budget_*`
        /// -- it tracks an *unbudgeted* slice of `header.insurance` that no
        /// `insurance_operator` can reach via `WithdrawInsuranceAsset`.
        pub protocol_fee_accrued_atoms: u128,
        /// Cumulative atoms ever paid out via `WithdrawProtocolFee` (tag 84).
        /// Monotonic, always `<= protocol_fee_accrued_atoms`. The claim
        /// capacity is `protocol_fee_accrued_atoms - protocol_fee_withdrawn_atoms`.
        pub protocol_fee_withdrawn_atoms: u128,
        // ── Fee-collection split (2026-07-19 design; 496 -> 576 B) ──────────
        // FIELD ORDER IS LOAD-BEARING. This struct derives bytemuck::Pod, which
        // forbids IMPLICIT padding. The struct ends at 496 B (a multiple of 16,
        // so u128-aligned). Placing the u16 shares first would push these u128s
        // to offset 502, forcing the compiler to insert implicit padding and
        // FAILING the Pod derive.
        //
        // EXACT TAIL LAYOUT (kept current — this is the comment a future editor
        // reads before touching the layout; it described the pre-creator-fee
        // shape until 2026-07-24):
        //   496..560  the four u128 accrued/withdrawn counters below
        //   560..566  the three u16 shares (creator, lp, insurance)
        //   566..568  `_padding_split: [u8; 2]`, aligning the next field to 8
        //   568..576  `creator_fee_claimable_atoms: u64` (creator-fee claim,
        //             2026-07-23) — this took the last 8 bytes of what was a
        //             `[u8; 10]` pad, so the struct still ends at exactly 576.
        // The struct's alignment is 16 (the u128s), and 576 is a multiple of 16,
        // so there is no trailing implicit padding for Pod to reject.
        /// Cumulative atoms accrued to the LP vault's claim. Monotonic.
        /// Claimed via `LpVaultCrankFees` (tag 78) into vault NAV.
        pub lp_fee_accrued_atoms: u128,
        /// Cumulative atoms already credited to the vault. `<= lp_fee_accrued_atoms`.
        pub lp_fee_withdrawn_atoms: u128,
        /// Cumulative atoms accrued to the insurance/staker leg. Monotonic.
        /// Claimed via `WithdrawInsuranceReserveToStake` (tag 87).
        pub insurance_reserve_accrued_atoms: u128,
        /// Cumulative atoms already pushed to the stake vault. `<= accrued`.
        pub insurance_reserve_withdrawn_atoms: u128,
        /// Creator's share of T in bps. Floor: <= MAX_CREATOR_SHARE_BPS.
        pub creator_share_bps: u16,
        /// LP's share of T in bps. Floor: >= MIN_LP_SHARE_BPS.
        pub lp_share_bps: u16,
        /// Insurance/staker share of T in bps. Floor: >= MIN_INSURANCE_SHARE_BPS.
        pub insurance_share_bps: u16,
        /// Explicit padding to the new counter's 8-byte alignment. Explicit
        /// because bytemuck::Pod forbids implicit padding. Was `[u8; 10]`
        /// before the creator-fee-claim change (2026-07-23) took the last
        /// 8 bytes of the pad; see `creator_fee_claimable_atoms`.
        pub _padding_split: [u8; 2],
        // ── Creator fee claim (2026-07-23 design) ───────────────────────────
        /// Creator's UNCLAIMED share of trade fees, in collateral atoms.
        /// Claimed via `WithdrawCreatorFee` (tag 90), which is the ONLY thing
        /// that decrements it.
        ///
        /// LAYOUT IS LOAD-BEARING AND DELIBERATELY CRAMPED. This occupies
        /// bytes 568..576 — the only 8-aligned slot inside the pre-existing
        /// 10-byte `_padding_split` — so `WRAPPER_CONFIG_LEN` stays 576 and NO
        /// existing field moves. Growing the struct would shift
        /// `MARKET_GROUP_OFF` (592) and every asset-profile offset, bricking
        /// the already-deployed 576-byte markets (a repeat of the 496->576
        /// offset incident). Deployed markets have these bytes zeroed (they
        /// were padding), so after an in-place upgrade the counter reads 0 and
        /// accrues fresh — no migration.
        ///
        /// ACCEPTED TRADE-OFFS (forced by the 10-byte budget): `u64` not
        /// `u128` (1.8e19 atoms ~ $18T at 6dp, a non-issue), and a single
        /// "claimable" counter rather than the accrued/withdrawn audit PAIR
        /// the protocol/LP/insurance legs use. Consequence: this counter is
        /// NOT monotonic, so it cannot be used to derive lifetime creator
        /// revenue — only the currently-claimable balance.
        pub creator_fee_claimable_atoms: u64,
    }

    // Compile-time guard (design §5.1 recommendation): a future field addition to
    // WrapperConfigV16 that forgets to bump WRAPPER_CONFIG_LEN in lockstep now fails
    // the build instead of silently desyncing the zero-copy layout. Complements the
    // existing runtime `wrapper_config_len_matches_struct_size` test below.
    const _: () = assert!(core::mem::size_of::<WrapperConfigV16>() == WRAPPER_CONFIG_LEN);

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct AssetOracleProfileV16 {
        pub oracle_mode: u8,
        pub oracle_leg_count: u8,
        pub oracle_leg_flags: u8,
        pub invert: u8,
        pub unit_scale: u32,
        pub conf_filter_bps: u16,
        pub backing_trade_fee_bps_long: u16,
        pub backing_trade_fee_bps_short: u16,
        pub backing_trade_fee_insurance_share_bps_long: u16,
        pub backing_trade_fee_insurance_share_bps_short: u16,
        pub _padding0: [u8; 6],
        pub insurance_authority: [u8; 32],
        pub insurance_operator: [u8; 32],
        pub backing_bucket_authority: [u8; 32],
        pub oracle_authority: [u8; 32],
        pub max_staleness_secs: u64,
        pub hybrid_soft_stale_slots: u64,
        pub mark_ewma_e6: u64,
        pub mark_ewma_last_slot: u64,
        pub mark_ewma_halflife_slots: u64,
        pub mark_min_fee: u64,
        pub oracle_target_price_e6: u64,
        pub oracle_target_publish_time: i64,
        pub last_good_oracle_slot: u64,
        pub oracle_leg_feeds: [[u8; 32]; ORACLE_LEG_CAP],
        pub oracle_leg_prices_e6: [u64; ORACLE_LEG_CAP],
        pub oracle_leg_publish_times: [i64; ORACLE_LEG_CAP],
        // Per-asset cold-storage admin (assets 1..N). Can rotate THIS asset's domain authorities
        // (insurance/operator/backing/oracle) and itself, and can be burned (set to 0). Isolated:
        // it can never act on another asset. Set to the activator at creation.
        pub asset_admin: [u8; 32],
    }

    /// Aggregate backing-domain accounting for an authority-controlled vault.
    /// This intentionally contains no per-depositor state; external authority
    /// programs can use these monotonic counters to run their own subledgers.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct BackingDomainLedgerAccountV16 {
        pub market_group: [u8; 32],
        pub authority: [u8; 32],
        pub total_principal_atoms: u128,
        pub total_deposited_atoms: u128,
        pub total_principal_withdrawn_atoms: u128,
        pub total_earnings_atoms: u128,
        pub total_earnings_withdrawn_atoms: u128,
        pub last_observed_bucket_earnings_atoms: u128,
        pub cumulative_loss_atoms: u128,
        pub cumulative_recovery_atoms: u128,
        pub last_observed_unavailable_principal_atoms: u128,
        pub domain: u16,
        pub _padding: [u8; 14],
    }

    impl BackingDomainLedgerAccountV16 {
        /// Farm-facing deterministic reward counter for this backing authority/domain.
        ///
        /// This is the LP-side `residual_received` scalar: a monotonic sum of realized
        /// backing loss observed by `SyncBackingDomainLedger`. The backing bucket's
        /// unavailable-principal delta is the trader-side cap source; the farm snapshots
        /// this value and rewards only `end - start`, optionally capped by its own
        /// fee-support policy.
        pub fn residual_received_atoms(&self) -> u128 {
            self.cumulative_loss_atoms
        }

        /// Monotonic recovery counter, kept separate so `residual_received_atoms` remains
        /// deterministic for start/end reward snapshots.
        pub fn residual_recovered_atoms(&self) -> u128 {
            self.cumulative_recovery_atoms
        }

        pub fn residual_received_delta_since(&self, snapshot: u128) -> Result<u128, ProgramError> {
            self.residual_received_atoms()
                .checked_sub(snapshot)
                .ok_or(PercolatorError::InvalidInstruction.into())
        }
    }

    /// Aggregate insurance accounting for an authority-controlled vault.
    /// This is not a user account and does not assign shares.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct InsuranceLedgerAccountV16 {
        pub market_group: [u8; 32],
        pub authority: [u8; 32],
        pub total_principal_atoms: u128,
        pub total_deposited_atoms: u128,
        pub total_withdrawn_atoms: u128,
        pub cumulative_profit_atoms: u128,
        pub cumulative_loss_atoms: u128,
        pub last_observed_insurance_atoms: u128,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct PortfolioMatcherConfigV16 {
        pub matcher_program: [u8; 32],
        pub matcher_context: [u8; 32],
        pub matcher_delegate: [u8; 32],
        pub enabled: u64,
    }

    pub type AssetOracleStorageV16 = [u8; ASSET_ORACLE_WRAPPER_LEN];
    pub type MarketViewMutV16<'a> = MarketGroupV16ViewMut<'a, AssetOracleStorageV16>;

    #[inline]
    fn read_u16(data: &[u8], off: usize) -> Result<u16, ProgramError> {
        let bytes: [u8; 2] = data
            .get(off..off + 2)
            .ok_or(PercolatorError::InvalidAccountLen)?
            .try_into()
            .unwrap();
        Ok(u16::from_le_bytes(bytes))
    }

    #[inline]
    fn read_u64(data: &[u8], off: usize) -> Result<u64, ProgramError> {
        let bytes: [u8; 8] = data
            .get(off..off + 8)
            .ok_or(PercolatorError::InvalidAccountLen)?
            .try_into()
            .unwrap();
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    fn write_header(data: &mut [u8], kind: u8) -> Result<(), ProgramError> {
        if data.len() < HEADER_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        data[8..10].copy_from_slice(&VERSION.to_le_bytes());
        data[10] = kind;
        for b in data[11..HEADER_LEN].iter_mut() {
            *b = 0;
        }
        Ok(())
    }

    #[inline]
    fn check_header(data: &[u8], kind: u8) -> Result<(), ProgramError> {
        if data.len() < HEADER_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if read_u64(data, 0)? != MAGIC {
            return Err(PercolatorError::NotInitialized.into());
        }
        if read_u16(data, 8)? != VERSION {
            return Err(PercolatorError::InvalidVersion.into());
        }
        if data[10] != kind {
            return Err(PercolatorError::InvalidAccountKind.into());
        }
        Ok(())
    }

    #[inline]
    pub fn check_portfolio_kind(data: &[u8]) -> Result<(), ProgramError> {
        check_header(data, KIND_PORTFOLIO)
    }

    #[inline]
    pub fn is_initialized(data: &[u8]) -> bool {
        data.len() >= HEADER_LEN && read_u64(data, 0).ok() == Some(MAGIC)
    }

    const MARKET_MATCHER_NONCE_OFF: usize = 11;
    const MARKET_MATCHER_NONCE_LEN: usize = HEADER_LEN - MARKET_MATCHER_NONCE_OFF;
    const MARKET_MATCHER_NONCE_MAX: u64 = (1u64 << (MARKET_MATCHER_NONCE_LEN * 8)) - 1;

    #[inline]
    fn read_market_matcher_request_nonce(data: &[u8]) -> Result<u64, ProgramError> {
        check_header(data, KIND_MARKET)?;
        let bytes = data
            .get(MARKET_MATCHER_NONCE_OFF..MARKET_MATCHER_NONCE_OFF + MARKET_MATCHER_NONCE_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let mut buf = [0u8; 8];
        buf[..MARKET_MATCHER_NONCE_LEN].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    }

    #[inline]
    pub fn next_market_matcher_req_id(data: &[u8]) -> Result<u64, ProgramError> {
        let nonce = read_market_matcher_request_nonce(data)?;
        let next = nonce
            .checked_add(1)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        if next > MARKET_MATCHER_NONCE_MAX {
            return Err(PercolatorError::EngineArithmeticOverflow.into());
        }
        Ok(next)
    }

    #[inline]
    pub fn commit_market_matcher_req_id(
        data: &mut [u8],
        req_id: u64,
    ) -> Result<(), ProgramError> {
        check_header(data, KIND_MARKET)?;
        if req_id == 0 || req_id > MARKET_MATCHER_NONCE_MAX {
            return Err(PercolatorError::EngineArithmeticOverflow.into());
        }
        data.get_mut(
            MARKET_MATCHER_NONCE_OFF..MARKET_MATCHER_NONCE_OFF + MARKET_MATCHER_NONCE_LEN,
        )
        .ok_or(PercolatorError::InvalidAccountLen)?
        .copy_from_slice(&req_id.to_le_bytes()[..MARKET_MATCHER_NONCE_LEN]);
        Ok(())
    }

    pub const fn backing_domain_ledger_account_len() -> usize {
        HEADER_LEN + core::mem::size_of::<BackingDomainLedgerAccountV16>()
    }

    pub const fn insurance_ledger_account_len() -> usize {
        HEADER_LEN + core::mem::size_of::<InsuranceLedgerAccountV16>()
    }

    #[inline]
    fn matcher_config_bytes(data: &[u8]) -> Result<&[u8], ProgramError> {
        data.get(
            PORTFOLIO_MATCHER_CONFIG_OFF
                ..PORTFOLIO_MATCHER_CONFIG_OFF + PORTFOLIO_MATCHER_CONFIG_LEN,
        )
        .ok_or(PercolatorError::InvalidAccountLen.into())
    }

    #[inline]
    fn matcher_config_bytes_mut(data: &mut [u8]) -> Result<&mut [u8], ProgramError> {
        data.get_mut(
            PORTFOLIO_MATCHER_CONFIG_OFF
                ..PORTFOLIO_MATCHER_CONFIG_OFF + PORTFOLIO_MATCHER_CONFIG_LEN,
        )
        .ok_or(PercolatorError::InvalidAccountLen.into())
    }

    #[inline]
    pub fn read_portfolio_matcher_config(
        data: &[u8],
    ) -> Result<PortfolioMatcherConfigV16, ProgramError> {
        check_header(data, KIND_PORTFOLIO)?;
        let bytes = matcher_config_bytes(data)?;
        let config_len = core::mem::size_of::<PortfolioMatcherConfigV16>();
        let cfg: PortfolioMatcherConfigV16 = bytemuck::pod_read_unaligned(
            bytes
                .get(..config_len)
                .ok_or(PercolatorError::InvalidAccountLen)?,
        );
        if cfg.enabled > 1 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(cfg)
    }

    #[inline]
    pub fn write_portfolio_matcher_config(
        data: &mut [u8],
        cfg: &PortfolioMatcherConfigV16,
    ) -> Result<(), ProgramError> {
        check_header(data, KIND_PORTFOLIO)?;
        if cfg.enabled > 1 {
            return Err(ProgramError::InvalidAccountData);
        }
        let bytes = matcher_config_bytes_mut(data)?;
        for b in bytes.iter_mut() {
            *b = 0;
        }
        let config_len = core::mem::size_of::<PortfolioMatcherConfigV16>();
        bytes
            .get_mut(..config_len)
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(cfg));
        Ok(())
    }

    #[inline]
    fn validate_backing_domain_ledger(
        ledger: &BackingDomainLedgerAccountV16,
    ) -> Result<(), ProgramError> {
        if ledger.market_group == [0u8; 32]
            || ledger.authority == [0u8; 32]
            || ledger._padding != [0u8; 14]
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    #[inline]
    pub fn read_backing_domain_ledger(
        data: &[u8],
    ) -> Result<BackingDomainLedgerAccountV16, ProgramError> {
        if data.len() < backing_domain_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_BACKING_DOMAIN_LEDGER)?;
        let bytes = data
            .get(HEADER_LEN..backing_domain_ledger_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let ledger = bytemuck::pod_read_unaligned(bytes);
        validate_backing_domain_ledger(&ledger)?;
        Ok(ledger)
    }

    #[inline]
    pub fn write_backing_domain_ledger(
        data: &mut [u8],
        ledger: &BackingDomainLedgerAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < backing_domain_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_BACKING_DOMAIN_LEDGER)?;
        validate_backing_domain_ledger(ledger)?;
        data.get_mut(HEADER_LEN..backing_domain_ledger_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(ledger));
        Ok(())
    }

    #[inline]
    pub fn init_backing_domain_ledger(
        data: &mut [u8],
        ledger: &BackingDomainLedgerAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < backing_domain_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_BACKING_DOMAIN_LEDGER)?;
        write_backing_domain_ledger(data, ledger)
    }

    #[inline]
    fn validate_insurance_ledger(ledger: &InsuranceLedgerAccountV16) -> Result<(), ProgramError> {
        if ledger.market_group == [0u8; 32] || ledger.authority == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    #[inline]
    pub fn read_insurance_ledger(data: &[u8]) -> Result<InsuranceLedgerAccountV16, ProgramError> {
        if data.len() < insurance_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_INSURANCE_LEDGER)?;
        let bytes = data
            .get(HEADER_LEN..insurance_ledger_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let ledger = bytemuck::pod_read_unaligned(bytes);
        validate_insurance_ledger(&ledger)?;
        Ok(ledger)
    }

    #[inline]
    pub fn write_insurance_ledger(
        data: &mut [u8],
        ledger: &InsuranceLedgerAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < insurance_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_INSURANCE_LEDGER)?;
        validate_insurance_ledger(ledger)?;
        data.get_mut(HEADER_LEN..insurance_ledger_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(ledger));
        Ok(())
    }

    #[inline]
    pub fn init_insurance_ledger(
        data: &mut [u8],
        ledger: &InsuranceLedgerAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < insurance_ledger_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_INSURANCE_LEDGER)?;
        write_insurance_ledger(data, ledger)
    }

    #[inline]
    fn map_account_wire_error(_: V16Error) -> ProgramError {
        ProgramError::InvalidAccountData
    }

    #[inline]
    fn read_wrapper_config_from_bytes(data: &[u8]) -> Result<WrapperConfigV16, ProgramError> {
        let bytes = data
            .get(HEADER_LEN..HEADER_LEN + WRAPPER_CONFIG_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let config = bytemuck::pod_read_unaligned(bytes);
        validate_wrapper_config(&config)?;
        Ok(config)
    }

    #[cfg(not(target_os = "solana"))]
    fn read_wrapper_config_boxed_from_bytes(
        data: &[u8],
    ) -> Result<Box<WrapperConfigV16>, ProgramError> {
        let bytes = data
            .get(HEADER_LEN..HEADER_LEN + WRAPPER_CONFIG_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let mut boxed = Box::<WrapperConfigV16>::new_uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                boxed.as_mut_ptr() as *mut u8,
                WRAPPER_CONFIG_LEN,
            );
            let boxed = boxed.assume_init();
            validate_wrapper_config(boxed.as_ref())?;
            Ok(boxed)
        }
    }

    // NOTE: this runs at LOAD time (every `read_wrapper_config_from_bytes` /
    // `read_wrapper_config_boxed_from_bytes` call, i.e. every instruction
    // that deserializes an existing market's config). The fee-split floor
    // (creator<=45%/LP>=40%/insurance>=15%) is deliberately NOT checked here:
    // doing so would retroactively brick every market created before that
    // floor existed, since their stored split may not satisfy it. The floor is
    // enforced only where a NEW split is written: `handle_update_fee_split`
    // (tag 86), via `policy_v16::validate_fee_split`.
    //
    // CORRECTED: this used to name `handle_update_backing_fee_policy` /
    // `handle_update_trade_fee_policy` and `policy_v16::fee_split_floor_ok` as
    // the enforcement site. Both setters dropped that check, and
    // `fee_split_floor_ok` is retired with no live call sites. Tag 86 is now
    // the ONLY floor enforcement point in the program.
    #[inline]
    fn validate_wrapper_config(config: &WrapperConfigV16) -> Result<(), ProgramError> {
        if config.collateral_mint == [0u8; 32]
            || (config.secondary_collateral_mint != [0u8; 32]
                && config.secondary_collateral_mint == config.collateral_mint)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        if !insurance_withdraw_policy_shape_ok(
            config.insurance_withdraw_max_bps,
            config.insurance_withdraw_deposits_only,
            config.insurance_withdraw_cooldown_slots,
        ) || config.liquidation_cranker_fee_share_bps > 10_000
            || config.maintenance_cranker_fee_share_bps > 10_000
            || !backing_trade_fee_policy_shape_ok(
                config.backing_trade_fee_bps_long,
                config.backing_trade_fee_insurance_share_bps_long,
            )
            || !backing_trade_fee_policy_shape_ok(
                config.backing_trade_fee_bps_short,
                config.backing_trade_fee_insurance_share_bps_short,
            )
            || config.conf_filter_bps > 10_000
            || config.invert > 1
            || config._padding0 != 0
            || config.fee_redirect_to_market_0_bps > 10_000
            || config.oracle_leg_count as usize > ORACLE_LEG_CAP
            || (config.oracle_leg_flags & !ORACLE_LEG_FLAGS_MASK) != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let base_backing_fee_policy_count = (config.backing_trade_fee_bps_long != 0) as u16
            + (config.backing_trade_fee_bps_short != 0) as u16;
        if config.backing_trade_fee_policy_count < base_backing_fee_policy_count {
            return Err(ProgramError::InvalidAccountData);
        }

        match config.oracle_mode {
            ORACLE_MODE_MANUAL => {
                if config.oracle_leg_count != 0 || config.oracle_leg_flags != 0 {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_HYBRID_AFTER_HOURS => {
                if config.oracle_leg_count == 0
                    || config.max_staleness_secs == 0
                    || config.hybrid_soft_stale_slots == 0
                    || !valid_engine_oracle_price(config.mark_ewma_e6)
                    || !valid_engine_oracle_price(config.oracle_target_price_e6)
                    || !crate::oracle_v16::oracle_leg_config_ok(
                        config.oracle_leg_count,
                        config.oracle_leg_flags,
                        &config.oracle_leg_feeds,
                    )
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_EWMA_MARK => {
                if config.oracle_leg_count != 0
                    || config.oracle_leg_flags != 0
                    || config.invert != 0
                    || config.unit_scale != 0
                    || config.conf_filter_bps != 0
                    || config.max_staleness_secs != 0
                    || config.hybrid_soft_stale_slots != 0
                    || !valid_engine_oracle_price(config.mark_ewma_e6)
                    || !valid_engine_oracle_price(config.oracle_target_price_e6)
                    || config.mark_ewma_halflife_slots == 0
                    || config.oracle_leg_feeds.iter().any(|f| *f != [0u8; 32])
                    || config.oracle_leg_prices_e6.iter().any(|p| *p != 0)
                    || config.oracle_leg_publish_times.iter().any(|t| *t != 0)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_AUTH_MARK => {
                if config.oracle_leg_count != 0
                    || config.oracle_leg_flags != 0
                    || config.invert != 0
                    || config.unit_scale != 0
                    || config.conf_filter_bps != 0
                    || config.max_staleness_secs != 0
                    || config.hybrid_soft_stale_slots != 0
                    || !valid_engine_oracle_price(config.mark_ewma_e6)
                    || !valid_engine_oracle_price(config.oracle_target_price_e6)
                    || config.mark_ewma_e6 != config.oracle_target_price_e6
                    || config.mark_ewma_halflife_slots != 0
                    || config.mark_min_fee != 0
                    || config.oracle_leg_feeds.iter().any(|f| *f != [0u8; 32])
                    || config.oracle_leg_prices_e6.iter().any(|p| *p != 0)
                    || config.oracle_leg_publish_times.iter().any(|t| *t != 0)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            _ => return Err(ProgramError::InvalidAccountData),
        }

        Ok(())
    }

    #[inline]
    pub(super) fn insurance_withdraw_policy_shape_ok(
        max_bps: u16,
        deposits_only: u8,
        cooldown_slots: u64,
    ) -> bool {
        if max_bps > 10_000 || deposits_only > 1 {
            return false;
        }
        if max_bps == 0 || deposits_only != 0 {
            return true;
        }
        max_bps < 10_000 && cooldown_slots != 0
    }

    // NOTE: called from BOTH `read_asset_oracle_profile`/`validate_wrapper_config`
    // (load time) AND `write_asset_oracle_profile` (set time) via
    // `validate_asset_oracle_profile` -- i.e. on every deserialize of an
    // existing market's config/profile, not only when a setter runs. Only
    // basic shape (bounds + the fee==0-implies-share==0 pairing) belongs
    // here. The fee-split FLOOR (creator<=45%/LP>=40%/insurance>=15%) must
    // never be added to this function: it would retroactively brick every
    // market whose already-stored split doesn't satisfy the new floor. That
    // floor is enforced only where a NEW split is written:
    // `handle_update_fee_split` (tag 86), via `policy_v16::validate_fee_split`.
    //
    // CORRECTED: this used to name the two backing/trade-fee-policy setters and
    // `policy_v16::fee_split_floor_ok`. Both setters dropped that check and
    // `fee_split_floor_ok` is retired with no live call sites.
    #[inline]
    pub(crate) fn backing_trade_fee_policy_shape_ok(
        fee_bps: u16,
        insurance_share_bps: u16,
    ) -> bool {
        fee_bps <= 10_000
            && insurance_share_bps <= 10_000
            && (fee_bps != 0 || insurance_share_bps == 0)
    }

    #[inline]
    fn valid_engine_oracle_price(price: u64) -> bool {
        price != 0 && price <= percolator::MAX_ORACLE_PRICE
    }

    #[inline]
    pub fn validate_asset_oracle_profile(
        profile: &AssetOracleProfileV16,
    ) -> Result<(), ProgramError> {
        if profile.conf_filter_bps > 10_000
            || !backing_trade_fee_policy_shape_ok(
                profile.backing_trade_fee_bps_long,
                profile.backing_trade_fee_insurance_share_bps_long,
            )
            || !backing_trade_fee_policy_shape_ok(
                profile.backing_trade_fee_bps_short,
                profile.backing_trade_fee_insurance_share_bps_short,
            )
            || profile.invert > 1
            || profile._padding0 != [0u8; 6]
            || profile.oracle_leg_count as usize > ORACLE_LEG_CAP
            || (profile.oracle_leg_flags & !ORACLE_LEG_FLAGS_MASK) != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }

        match profile.oracle_mode {
            ORACLE_MODE_MANUAL => {
                if profile.oracle_leg_count != 0
                    || profile.oracle_leg_flags != 0
                    || profile.oracle_leg_feeds.iter().any(|f| *f != [0u8; 32])
                    || profile.oracle_leg_prices_e6.iter().any(|p| *p != 0)
                    || profile.oracle_leg_publish_times.iter().any(|t| *t != 0)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_HYBRID_AFTER_HOURS => {
                if profile.oracle_leg_count == 0
                    || profile.max_staleness_secs == 0
                    // B-11: cap oracle staleness at MAX_ORACLE_STALENESS_SECS (defence-in-depth —
                    // also enforced at instruction level). Keeps state-layer self-consistent so
                    // stored profiles can never hold a value that would be rejected on re-activation.
                    || profile.max_staleness_secs > crate::constants::MAX_ORACLE_STALENESS_SECS
                    || profile.hybrid_soft_stale_slots == 0
                    || !valid_engine_oracle_price(profile.mark_ewma_e6)
                    || !valid_engine_oracle_price(profile.oracle_target_price_e6)
                    || profile.mark_ewma_halflife_slots == 0
                    || !crate::oracle_v16::oracle_leg_config_ok(
                        profile.oracle_leg_count,
                        profile.oracle_leg_flags,
                        &profile.oracle_leg_feeds,
                    )
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_EWMA_MARK => {
                if profile.oracle_leg_count != 0
                    || profile.oracle_leg_flags != 0
                    || profile.invert != 0
                    || profile.unit_scale != 0
                    || profile.conf_filter_bps != 0
                    || profile.max_staleness_secs != 0
                    || profile.hybrid_soft_stale_slots != 0
                    || !valid_engine_oracle_price(profile.mark_ewma_e6)
                    || !valid_engine_oracle_price(profile.oracle_target_price_e6)
                    || profile.mark_ewma_halflife_slots == 0
                    || profile.oracle_leg_feeds.iter().any(|f| *f != [0u8; 32])
                    || profile.oracle_leg_prices_e6.iter().any(|p| *p != 0)
                    || profile.oracle_leg_publish_times.iter().any(|t| *t != 0)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            ORACLE_MODE_AUTH_MARK => {
                if profile.oracle_leg_count != 0
                    || profile.oracle_leg_flags != 0
                    || profile.invert != 0
                    || profile.unit_scale != 0
                    || profile.conf_filter_bps != 0
                    || profile.max_staleness_secs != 0
                    || profile.hybrid_soft_stale_slots != 0
                    || !valid_engine_oracle_price(profile.mark_ewma_e6)
                    || !valid_engine_oracle_price(profile.oracle_target_price_e6)
                    || profile.mark_ewma_e6 != profile.oracle_target_price_e6
                    || profile.mark_ewma_halflife_slots != 0
                    || profile.mark_min_fee != 0
                    || profile.oracle_leg_feeds.iter().any(|f| *f != [0u8; 32])
                    || profile.oracle_leg_prices_e6.iter().any(|p| *p != 0)
                    || profile.oracle_leg_publish_times.iter().any(|t| *t != 0)
                {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            _ => return Err(ProgramError::InvalidAccountData),
        }

        Ok(())
    }

    #[inline]
    pub fn manual_asset_oracle_profile(initial_price: u64, slot: u64) -> AssetOracleProfileV16 {
        AssetOracleProfileV16 {
            oracle_mode: ORACLE_MODE_MANUAL,
            oracle_leg_count: 0,
            oracle_leg_flags: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 0,
            backing_trade_fee_bps_long: 0,
            backing_trade_fee_bps_short: 0,
            backing_trade_fee_insurance_share_bps_long: 0,
            backing_trade_fee_insurance_share_bps_short: 0,
            _padding0: [0u8; 6],
            insurance_authority: [0u8; 32],
            insurance_operator: [0u8; 32],
            backing_bucket_authority: [0u8; 32],
            oracle_authority: [0u8; 32],
            max_staleness_secs: 0,
            hybrid_soft_stale_slots: 0,
            mark_ewma_e6: initial_price,
            mark_ewma_last_slot: slot,
            mark_ewma_halflife_slots: crate::constants::DEFAULT_MARK_EWMA_HALFLIFE_SLOTS,
            mark_min_fee: 0,
            oracle_target_price_e6: initial_price,
            oracle_target_publish_time: 0,
            last_good_oracle_slot: slot,
            oracle_leg_feeds: [[0u8; 32]; ORACLE_LEG_CAP],
            oracle_leg_prices_e6: [0u64; ORACLE_LEG_CAP],
            oracle_leg_publish_times: [0i64; ORACLE_LEG_CAP],
            asset_admin: [0u8; 32],
        }
    }

    pub fn asset_oracle_profile_from_config(config: &WrapperConfigV16) -> AssetOracleProfileV16 {
        AssetOracleProfileV16 {
            oracle_mode: config.oracle_mode,
            oracle_leg_count: config.oracle_leg_count,
            oracle_leg_flags: config.oracle_leg_flags,
            invert: config.invert,
            unit_scale: config.unit_scale,
            conf_filter_bps: config.conf_filter_bps,
            backing_trade_fee_bps_long: config.backing_trade_fee_bps_long,
            backing_trade_fee_bps_short: config.backing_trade_fee_bps_short,
            backing_trade_fee_insurance_share_bps_long: config
                .backing_trade_fee_insurance_share_bps_long,
            backing_trade_fee_insurance_share_bps_short: config
                .backing_trade_fee_insurance_share_bps_short,
            _padding0: [0u8; 6],
            // At InitMarket the market key bootstraps asset 0 exactly like an activator bootstraps a
            // permissionless asset 1..N: it is asset 0's cold-storage admin and all its sub-authorities.
            insurance_authority: config.marketauth,
            insurance_operator: config.marketauth,
            backing_bucket_authority: config.marketauth,
            oracle_authority: config.marketauth,
            max_staleness_secs: config.max_staleness_secs,
            hybrid_soft_stale_slots: config.hybrid_soft_stale_slots,
            mark_ewma_e6: config.mark_ewma_e6,
            mark_ewma_last_slot: config.mark_ewma_last_slot,
            mark_ewma_halflife_slots: config.mark_ewma_halflife_slots,
            mark_min_fee: config.mark_min_fee,
            oracle_target_price_e6: config.oracle_target_price_e6,
            oracle_target_publish_time: config.oracle_target_publish_time,
            last_good_oracle_slot: config.last_good_oracle_slot,
            oracle_leg_feeds: config.oracle_leg_feeds,
            oracle_leg_prices_e6: config.oracle_leg_prices_e6,
            oracle_leg_publish_times: config.oracle_leg_publish_times,
            asset_admin: config.marketauth,
        }
    }

    #[inline]
    fn write_wrapper_config_to_bytes(
        data: &mut [u8],
        config: &WrapperConfigV16,
    ) -> Result<(), ProgramError> {
        validate_wrapper_config(config)?;
        data.get_mut(HEADER_LEN..HEADER_LEN + WRAPPER_CONFIG_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(config));
        Ok(())
    }

    #[inline]
    pub fn market_account_len_for_capacity(capacity: usize) -> Result<usize, ProgramError> {
        let dynamic_len = MarketGroupV16HeaderAccount::dynamic_market_group_account_len::<
            AssetOracleStorageV16,
        >(capacity)
        .map_err(map_account_wire_error)?;
        MARKET_GROUP_OFF
            .checked_add(dynamic_len)
            .ok_or(PercolatorError::InvalidAccountLen.into())
    }

    #[inline]
    pub fn portfolio_account_len_for_market_slots(
        _max_market_slots: usize,
    ) -> Result<usize, ProgramError> {
        // Fixed-size: source-domains are a fixed sparse array embedded in PORTFOLIO_STATE_LEN.
        // Independent of the market's asset count N (O(1) portfolio). The wrapper-owned
        // matcher config tail lives after the engine portfolio body.
        Ok(PORTFOLIO_ACCOUNT_LEN)
    }

    #[inline]
    pub fn market_slot_capacity(data: &[u8]) -> Result<usize, ProgramError> {
        if data.len() < MARKET_GROUP_OFF + MARKET_GROUP_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        MarketGroupV16HeaderAccount::dynamic_asset_slot_capacity_from_account_len::<
            AssetOracleStorageV16,
        >(data.len() - MARKET_GROUP_OFF)
        .map_err(map_account_wire_error)
    }

    #[inline]
    fn validate_market_dynamic_len(data: &[u8]) -> Result<usize, ProgramError> {
        let capacity = market_slot_capacity(data)?;
        MarketGroupV16HeaderAccount::validate_dynamic_market_group_account_len::<
            AssetOracleStorageV16,
        >(data.len() - MARKET_GROUP_OFF, capacity)
        .map_err(map_account_wire_error)?;
        Ok(capacity)
    }

    #[inline]
    fn dynamic_slot_offset(asset_index: usize) -> Result<usize, ProgramError> {
        Ok(MARKET_GROUP_OFF
            + MarketGroupV16HeaderAccount::dynamic_asset_slot_offset::<AssetOracleStorageV16>(
                asset_index,
            )
            .map_err(map_account_wire_error)?)
    }

    #[inline]
    fn asset_slot_range(asset_index: usize) -> Result<core::ops::Range<usize>, ProgramError> {
        let start = dynamic_slot_offset(asset_index)?
            .checked_add(ASSET_ORACLE_WRAPPER_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        Ok(start..start + core::mem::size_of::<EngineAssetSlotV16Account>())
    }

    #[inline]
    fn asset_oracle_profile_range(
        data: &[u8],
        asset_index: usize,
    ) -> Result<core::ops::Range<usize>, ProgramError> {
        let capacity = market_slot_capacity(data)?;
        if asset_index >= capacity {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let start = dynamic_slot_offset(asset_index)?;
        Ok(start..start + ASSET_ORACLE_PROFILE_LEN)
    }

    pub fn read_asset_oracle_profile(
        data: &[u8],
        asset_index: usize,
    ) -> Result<AssetOracleProfileV16, ProgramError> {
        check_header(data, KIND_MARKET)?;
        let range = asset_oracle_profile_range(data, asset_index)?;
        let bytes = data.get(range).ok_or(PercolatorError::InvalidAccountLen)?;
        let profile: AssetOracleProfileV16 = bytemuck::pod_read_unaligned(bytes);
        validate_asset_oracle_profile(&profile)?;
        Ok(profile)
    }

    pub fn read_market_config_mode_and_capacity(
        data: &[u8],
    ) -> Result<(WrapperConfigV16, MarketModeV16, usize, usize), ProgramError> {
        check_header(data, KIND_MARKET)?;
        validate_market_dynamic_len(data)?;
        let config = read_wrapper_config_from_bytes(data)?;
        let header = market_header(data)?;
        let engine_config = header
            .config
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        Ok((
            config,
            decode_market_mode(header.mode)?,
            engine_config.max_market_slots as usize,
            header.asset_slot_capacity.get() as usize,
        ))
    }

    pub fn write_asset_oracle_profile(
        data: &mut [u8],
        asset_index: usize,
        profile: &AssetOracleProfileV16,
    ) -> Result<(), ProgramError> {
        check_header(data, KIND_MARKET)?;
        validate_asset_oracle_profile(profile)?;
        let range = asset_oracle_profile_range(data, asset_index)?;
        data.get_mut(range)
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(profile));
        Ok(())
    }

    pub fn write_wrapper_config(
        data: &mut [u8],
        config: &WrapperConfigV16,
    ) -> Result<(), ProgramError> {
        check_header(data, KIND_MARKET)?;
        write_wrapper_config_to_bytes(data, config)
    }

    pub fn market_view_mut(
        data: &mut [u8],
    ) -> Result<(WrapperConfigV16, MarketViewMutV16<'_>), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        let config = read_wrapper_config_from_bytes(data)?;
        let capacity = validate_market_dynamic_len(data)?;
        let state_data = data
            .get_mut(MARKET_GROUP_OFF..)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let header_len = core::mem::size_of::<MarketGroupV16HeaderAccount>();
        let (header_bytes, market_bytes) = state_data.split_at_mut(header_len);
        let header = bytemuck::try_from_bytes_mut::<MarketGroupV16HeaderAccount>(header_bytes)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        let configured = header.config.max_market_slots.get() as usize;
        if configured == 0 || configured > capacity {
            return Err(ProgramError::InvalidAccountData);
        }
        let used_len = capacity
            .checked_mul(core::mem::size_of::<Market<AssetOracleStorageV16>>())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let markets_bytes = market_bytes
            .get_mut(..used_len)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let markets =
            bytemuck::try_cast_slice_mut::<u8, Market<AssetOracleStorageV16>>(markets_bytes)
                .map_err(|_| ProgramError::InvalidAccountData)?;
        Ok((config, MarketGroupV16ViewMut::new(header, markets)))
    }

    pub fn activate_dynamic_asset_slot(
        data: &mut [u8],
        asset_index: usize,
        now_slot: u64,
        initial_price: u64,
        insurance_authority: [u8; 32],
        insurance_operator: [u8; 32],
        backing_bucket_authority: [u8; 32],
        oracle_authority: [u8; 32],
    ) -> Result<AssetOracleProfileV16, ProgramError> {
        if insurance_authority == [0u8; 32]
            || insurance_operator == [0u8; 32]
            || backing_bucket_authority == [0u8; 32]
            || oracle_authority == [0u8; 32]
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        check_header(data, KIND_MARKET)?;
        let capacity = validate_market_dynamic_len(data)?;
        if asset_index >= capacity || asset_index > u32::MAX as usize {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let mut header = *market_header(data)?;
        let engine_config = header
            .config
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        let old_n = engine_config.max_market_slots as usize;
        if asset_index != old_n {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let new_n = asset_index
            .checked_add(1)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let mut slot = *asset_slot_wire(data, asset_index)?;
        header
            .grow_asset_slot_capacity_not_atomic(capacity as u32, new_n as u32)
            .map_err(map_account_wire_error)?;
        header
            .activate_empty_asset_slot_not_atomic(
                asset_index as u32,
                &mut slot,
                initial_price,
                now_slot,
            )
            .map_err(map_account_wire_error)?;
        *market_header_mut(data)? = header;
        *asset_slot_wire_mut(data, asset_index)? = slot;
        let mut profile = manual_asset_oracle_profile(initial_price, now_slot);
        profile.insurance_authority = insurance_authority;
        profile.insurance_operator = insurance_operator;
        profile.backing_bucket_authority = backing_bucket_authority;
        profile.oracle_authority = oracle_authority;
        Ok(profile)
    }

    fn init_asset_oracle_profiles(
        data: &mut [u8],
        profile: &AssetOracleProfileV16,
    ) -> Result<(), ProgramError> {
        validate_asset_oracle_profile(profile)?;
        let bytes = bytemuck::bytes_of(profile);
        let capacity = market_slot_capacity(data)?;
        let mut i = 0usize;
        while i < capacity {
            let range = asset_oracle_profile_range(data, i)?;
            data.get_mut(range)
                .ok_or(PercolatorError::InvalidAccountLen)?
                .copy_from_slice(bytes);
            i += 1;
        }
        Ok(())
    }

    #[inline]
    fn market_header(data: &[u8]) -> Result<&MarketGroupV16HeaderAccount, ProgramError> {
        let bytes = data
            .get(
                MARKET_GROUP_OFF
                    ..MARKET_GROUP_OFF + core::mem::size_of::<MarketGroupV16HeaderAccount>(),
            )
            .ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    /// `(max_abs_funding_e9_per_slot, max_accrual_dt_slots)` from the engine
    /// config. Both are market-wide, so a per-asset funding-feasibility check
    /// needs only these two plus the asset's own initial price.
    pub fn read_engine_funding_bounds(data: &[u8]) -> Result<(u64, u64), ProgramError> {
        check_header(data, KIND_MARKET)?;
        let engine_config = market_header(data)?
            .config
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        Ok((
            engine_config.max_abs_funding_e9_per_slot,
            engine_config.max_accrual_dt_slots,
        ))
    }

    #[inline]
    fn market_header_mut(
        data: &mut [u8],
    ) -> Result<&mut MarketGroupV16HeaderAccount, ProgramError> {
        let bytes = data
            .get_mut(
                MARKET_GROUP_OFF
                    ..MARKET_GROUP_OFF + core::mem::size_of::<MarketGroupV16HeaderAccount>(),
            )
            .ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes_mut(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    #[inline]
    fn asset_slot_wire(
        data: &[u8],
        asset_index: usize,
    ) -> Result<&EngineAssetSlotV16Account, ProgramError> {
        let range = asset_slot_range(asset_index)?;
        let bytes = data.get(range).ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    #[inline]
    fn asset_slot_wire_mut(
        data: &mut [u8],
        asset_index: usize,
    ) -> Result<&mut EngineAssetSlotV16Account, ProgramError> {
        let range = asset_slot_range(asset_index)?;
        let bytes = data
            .get_mut(range)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes_mut(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    #[inline]
    pub fn portfolio_wire(data: &[u8]) -> Result<&PortfolioAccountV16Account, ProgramError> {
        let bytes = data
            .get(HEADER_LEN..HEADER_LEN + core::mem::size_of::<PortfolioAccountV16Account>())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    #[inline]
    pub fn portfolio_wire_mut(
        data: &mut [u8],
    ) -> Result<&mut PortfolioAccountV16Account, ProgramError> {
        let bytes = data
            .get_mut(HEADER_LEN..HEADER_LEN + core::mem::size_of::<PortfolioAccountV16Account>())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        bytemuck::try_from_bytes_mut(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    #[inline]
    fn decode_market_mode(v: u8) -> Result<MarketModeV16, ProgramError> {
        match v {
            0 => Ok(MarketModeV16::Live),
            1 => Ok(MarketModeV16::Resolved),
            2 => Ok(MarketModeV16::Recovery),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    #[cfg(not(target_os = "solana"))]
    fn market_slots_from_wire(
        data: &[u8],
        capacity: usize,
        slot_count: usize,
    ) -> Result<Vec<EngineAssetSlotV16Account>, ProgramError> {
        if slot_count > capacity {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        let mut slots = Vec::with_capacity(slot_count);
        let mut i = 0usize;
        while i < slot_count {
            slots.push(*asset_slot_wire(data, i)?);
            i += 1;
        }
        Ok(slots)
    }

    #[cfg(not(target_os = "solana"))]
    fn source_credit_account_is_empty_for_activation(
        state: percolator::SourceCreditStateV16Account,
    ) -> bool {
        state.positive_claim_bound_num.get() == 0
            && state.exact_positive_claim_num.get() == 0
            && state.fresh_reserved_backing_num.get() == 0
            && state.spent_backing_num.get() == 0
            && state.provider_receivable_num.get() == 0
            && state.valid_liened_backing_num.get() == 0
            && state.impaired_liened_backing_num.get() == 0
            && state.insurance_credit_reserved_num.get() == 0
            && state.valid_liened_insurance_num.get() == 0
            && state.impaired_liened_insurance_num.get() == 0
            && state.credit_epoch.get() == 0
            && (state.credit_rate_num.get() == 0
                || state.credit_rate_num.get() == percolator::CREDIT_RATE_SCALE)
    }

    #[cfg(not(target_os = "solana"))]
    fn backing_bucket_account_is_empty_for_activation(
        state: percolator::BackingBucketV16Account,
    ) -> bool {
        state.market_id.get() == 0
            && state.fresh_unliened_backing_num.get() == 0
            && state.valid_liened_backing_num.get() == 0
            && state.consumed_liened_backing_num.get() == 0
            && state.impaired_liened_backing_num.get() == 0
            && state.expiry_slot.get() == 0
            && state.status == 0
    }

    #[cfg(not(target_os = "solana"))]
    fn insurance_reservation_account_is_empty_for_activation(
        state: percolator::InsuranceCreditReservationV16Account,
    ) -> bool {
        state.insurance_credit_reserved_num.get() == 0
            && state.valid_liened_insurance_num.get() == 0
            && state.impaired_liened_insurance_num.get() == 0
            && state.consumed_insurance_num.get() == 0
            && state.source_credit_epoch.get() == 0
    }

    #[cfg(not(target_os = "solana"))]
    fn asset_state_is_empty_for_activation(asset: AssetStateV16) -> bool {
        let a_shape = (asset.a_long == 0 && asset.a_short == 0)
            || (asset.a_long == percolator::ADL_ONE && asset.a_short == percolator::ADL_ONE);
        asset.lifecycle == percolator::AssetLifecycleV16::Disabled
            && asset.market_id == 0
            && a_shape
            && asset.k_long == 0
            && asset.k_short == 0
            && asset.f_long_num == 0
            && asset.f_short_num == 0
            && asset.k_epoch_start_long == 0
            && asset.k_epoch_start_short == 0
            && asset.f_epoch_start_long_num == 0
            && asset.f_epoch_start_short_num == 0
            && asset.b_long_num == 0
            && asset.b_short_num == 0
            && asset.b_epoch_start_long_num == 0
            && asset.b_epoch_start_short_num == 0
            && asset.oi_eff_long_q == 0
            && asset.oi_eff_short_q == 0
            && asset.stored_pos_count_long == 0
            && asset.stored_pos_count_short == 0
            && asset.stale_account_count_long == 0
            && asset.stale_account_count_short == 0
            && asset.pending_obligation_count_long == 0
            && asset.pending_obligation_count_short == 0
            && asset.loss_weight_sum_long == 0
            && asset.loss_weight_sum_short == 0
            && asset.social_loss_remainder_long_num == 0
            && asset.social_loss_remainder_short_num == 0
            && asset.social_loss_dust_long_num == 0
            && asset.social_loss_dust_short_num == 0
            && asset.explicit_unallocated_loss_long == 0
            && asset.explicit_unallocated_loss_short == 0
            && asset.retired_slot == 0
            && asset.raw_oracle_target_price == 0
            && asset.effective_price == 0
            && asset.fund_px_last == 0
            && asset.slot_last == 0
            && asset.epoch_long == 0
            && asset.epoch_short == 0
            && asset.mode_long == percolator::SideModeV16::Normal
            && asset.mode_short == percolator::SideModeV16::Normal
    }

    #[cfg(not(target_os = "solana"))]
    fn inactive_market_slot_is_empty_for_activation(
        slot: EngineAssetSlotV16Account,
    ) -> Result<bool, ProgramError> {
        let asset = slot
            .asset
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        Ok(asset_state_is_empty_for_activation(asset)
            && (slot.insurance_domain_budget_long.get() == 0
                || slot.insurance_domain_budget_long.get() == percolator::MAX_VAULT_TVL)
            && (slot.insurance_domain_budget_short.get() == 0
                || slot.insurance_domain_budget_short.get() == percolator::MAX_VAULT_TVL)
            && slot.insurance_domain_spent_long.get() == 0
            && slot.insurance_domain_spent_short.get() == 0
            && slot.pending_domain_loss_barrier_long.get() == 0
            && slot.pending_domain_loss_barrier_short.get() == 0
            && source_credit_account_is_empty_for_activation(slot.source_credit_long)
            && source_credit_account_is_empty_for_activation(slot.source_credit_short)
            && backing_bucket_account_is_empty_for_activation(slot.backing_long)
            && backing_bucket_account_is_empty_for_activation(slot.backing_short)
            && insurance_reservation_account_is_empty_for_activation(
                slot.insurance_reservation_long,
            )
            && insurance_reservation_account_is_empty_for_activation(
                slot.insurance_reservation_short,
            ))
    }

    #[cfg(not(target_os = "solana"))]
    fn market_from_wire_boxed(
        data: &[u8],
        read_full_capacity: bool,
    ) -> Result<Box<MarketGroupV16>, ProgramError> {
        let wire = market_header(data)?;
        let capacity = validate_market_dynamic_len(data)?;
        let configured = wire.config.max_market_slots.get() as usize;
        if configured > capacity {
            return Err(ProgramError::InvalidAccountData);
        }
        let slot_count = if read_full_capacity {
            capacity
        } else {
            configured
        };
        let slots = market_slots_from_wire(data, capacity, slot_count)?;
        let domain_count = slot_count
            .checked_mul(2)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let mut group = MarketGroupV16 {
            market_group_id: wire.market_group_id,
            config: wire
                .config
                .try_to_runtime()
                .map_err(map_account_wire_error)?,
            vault: wire.vault.get(),
            insurance: wire.insurance.get(),
            c_tot: wire.c_tot.get(),
            pnl_pos_tot: wire.pnl_pos_tot.get(),
            pnl_pos_bound_tot_num: wire.pnl_pos_bound_tot_num.get(),
            pnl_pos_bound_tot: wire.pnl_pos_bound_tot.get(),
            pnl_matured_pos_tot: wire.pnl_matured_pos_tot.get(),
            backing_provider_earnings_total: wire.backing_provider_earnings_total.get(),
            source_claim_bound_total_num: wire.source_claim_bound_total_num.get(),
            source_fresh_backing_total_num: wire.source_fresh_backing_total_num.get(),
            source_insurance_credit_reserved_total_atoms: wire
                .source_insurance_credit_reserved_total_atoms
                .get(),
            insurance_domain_budget_remaining_total: wire
                .insurance_domain_budget_remaining_total
                .get(),
            resolved_payout_blocker_count: wire.resolved_payout_blocker_count.get(),
            insurance_domain_budget: vec_with_value(domain_count, 0u128),
            insurance_domain_spent: vec_with_value(domain_count, 0u128),
            pending_domain_loss_barriers: vec_with_value(domain_count, 0u64),
            source_credit: vec_with_value(domain_count, SourceCreditStateV16::EMPTY),
            source_backing_buckets: vec_with_value(domain_count, BackingBucketV16::EMPTY),
            insurance_credit_reservations: vec_with_value(
                domain_count,
                InsuranceCreditReservationV16::EMPTY,
            ),
            materialized_portfolio_count: wire.materialized_portfolio_count.get(),
            stale_certificate_count: wire.stale_certificate_count.get(),
            b_stale_account_count: wire.b_stale_account_count.get(),
            negative_pnl_account_count: wire.negative_pnl_account_count.get(),
            risk_epoch: wire.risk_epoch.get(),
            asset_set_epoch: wire.asset_set_epoch.get(),
            asset_activation_count: wire.asset_activation_count.get(),
            last_asset_activation_slot: wire.last_asset_activation_slot.get(),
            next_market_id: wire.next_market_id.get(),
            oracle_epoch: wire.oracle_epoch.get(),
            funding_epoch: wire.funding_epoch.get(),
            slot_last: wire.slot_last.get(),
            current_slot: wire.current_slot.get(),
            assets: Vec::with_capacity(slot_count),
            bankruptcy_hlock_active: decode_bool(wire.bankruptcy_hlock_active)?,
            threshold_stress_active: decode_bool(wire.threshold_stress_active)?,
            loss_stale_active: decode_bool(wire.loss_stale_active)?,
            recovery_reason: wire
                .recovery_reason
                .try_to_runtime()
                .map_err(map_account_wire_error)?,
            mode: decode_market_mode(wire.mode)?,
            resolved_slot: wire.resolved_slot.get(),
            payout_snapshot: wire.payout_snapshot.get(),
            payout_snapshot_pnl_pos_tot: wire.payout_snapshot_pnl_pos_tot.get(),
            payout_snapshot_captured: decode_bool(wire.payout_snapshot_captured)?,
            resolved_payout_ledger: wire
                .resolved_payout_ledger
                .try_to_runtime()
                .map_err(map_account_wire_error)?,
        };
        let mut i = 0usize;
        while i < slot_count {
            let slot = slots[i];
            let (long_domain, short_domain) =
                v16_domain_pair_for_asset_index(i).map_err(map_account_wire_error)?;
            if i >= configured {
                if !inactive_market_slot_is_empty_for_activation(slot)? {
                    return Err(ProgramError::InvalidAccountData);
                }
                let mut asset = AssetStateV16::default();
                asset.lifecycle = percolator::AssetLifecycleV16::Disabled;
                asset.market_id = 0;
                group.assets.push(asset);
                i += 1;
                continue;
            }
            group.assets.push(
                slot.asset
                    .try_to_runtime()
                    .map_err(map_account_wire_error)?,
            );
            group.insurance_domain_budget[long_domain] = slot.insurance_domain_budget_long.get();
            group.insurance_domain_budget[short_domain] = slot.insurance_domain_budget_short.get();
            group.insurance_domain_spent[long_domain] = slot.insurance_domain_spent_long.get();
            group.insurance_domain_spent[short_domain] = slot.insurance_domain_spent_short.get();
            group.pending_domain_loss_barriers[long_domain] =
                slot.pending_domain_loss_barrier_long.get();
            group.pending_domain_loss_barriers[short_domain] =
                slot.pending_domain_loss_barrier_short.get();
            group.source_credit[long_domain] = slot
                .source_credit_long
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            group.source_credit[short_domain] = slot
                .source_credit_short
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            group.source_backing_buckets[long_domain] = slot
                .backing_long
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            group.source_backing_buckets[short_domain] = slot
                .backing_short
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            group.insurance_credit_reservations[long_domain] = slot
                .insurance_reservation_long
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            group.insurance_credit_reservations[short_domain] = slot
                .insurance_reservation_short
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            i += 1;
        }
        Ok(Box::new(group))
    }

    #[cfg(not(target_os = "solana"))]
    fn write_market_wire(data: &mut [u8], group: &MarketGroupV16) -> Result<(), ProgramError> {
        let capacity = validate_market_dynamic_len(data)?;
        if capacity < group.config.max_market_slots as usize {
            return Err(ProgramError::InvalidAccountData);
        }
        let storage_domains = group
            .assets
            .len()
            .checked_mul(2)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        if group.insurance_domain_budget.len() < storage_domains
            || group.insurance_domain_spent.len() < storage_domains
            || group.pending_domain_loss_barriers.len() < storage_domains
            || group.source_credit.len() < storage_domains
            || group.source_backing_buckets.len() < storage_domains
            || group.insurance_credit_reservations.len() < storage_domains
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let header = market_header_mut(data)?;
        header.market_group_id = group.market_group_id;
        header.config = percolator::V16ConfigAccount::from_runtime(&group.config);
        header.asset_slot_capacity = percolator::V16PodU32::new(
            u32::try_from(capacity).map_err(|_| PercolatorError::InvalidAccountLen)?,
        );
        header.vault = percolator::V16PodU128::new(group.vault);
        header.insurance = percolator::V16PodU128::new(group.insurance);
        header.c_tot = percolator::V16PodU128::new(group.c_tot);
        header.pnl_pos_tot = percolator::V16PodU128::new(group.pnl_pos_tot);
        header.pnl_pos_bound_tot_num = percolator::V16PodU128::new(group.pnl_pos_bound_tot_num);
        header.pnl_pos_bound_tot = percolator::V16PodU128::new(group.pnl_pos_bound_tot);
        header.pnl_matured_pos_tot = percolator::V16PodU128::new(group.pnl_matured_pos_tot);
        // Recompute the O(1) market aggregate totals from the mirror's per-domain data so a host
        // read -> mutate -> write round-trip serializes them consistently with the per-domain state
        // (the engine maintains these incrementally on-chain).
        {
            let mut earnings = 0u128;
            for b in &group.source_backing_buckets {
                earnings = earnings.saturating_add(b.utilization_fee_earnings);
            }
            let mut claim_bound = 0u128;
            let mut fresh_backing = 0u128;
            let mut ins_reserved = 0u128;
            for s in &group.source_credit {
                claim_bound = claim_bound.saturating_add(s.positive_claim_bound_num);
                fresh_backing = fresh_backing.saturating_add(s.fresh_reserved_backing_num);
                let num = s.insurance_credit_reserved_num;
                let whole = num / percolator::BOUND_SCALE;
                let atoms = if num % percolator::BOUND_SCALE == 0 {
                    whole
                } else {
                    whole.saturating_add(1)
                };
                ins_reserved = ins_reserved.saturating_add(atoms);
            }
            let mut budget_remaining = 0u128;
            for (d, &budget) in group.insurance_domain_budget.iter().enumerate() {
                let spent = group.insurance_domain_spent.get(d).copied().unwrap_or(0);
                budget_remaining = budget_remaining.saturating_add(budget.saturating_sub(spent));
            }
            header.backing_provider_earnings_total = percolator::V16PodU128::new(earnings);
            header.source_claim_bound_total_num = percolator::V16PodU128::new(claim_bound);
            header.source_fresh_backing_total_num = percolator::V16PodU128::new(fresh_backing);
            header.source_insurance_credit_reserved_total_atoms =
                percolator::V16PodU128::new(ins_reserved);
            header.insurance_domain_budget_remaining_total =
                percolator::V16PodU128::new(budget_remaining);
            // #5: per-asset position/stale counts + per-domain pending loss barriers.
            let mut blockers = 0u64;
            for (i, a) in group.assets.iter().enumerate() {
                blockers = blockers
                    .saturating_add(a.stored_pos_count_long)
                    .saturating_add(a.stored_pos_count_short)
                    .saturating_add(a.stale_account_count_long)
                    .saturating_add(a.stale_account_count_short)
                    .saturating_add(
                        group
                            .pending_domain_loss_barriers
                            .get(2 * i)
                            .copied()
                            .unwrap_or(0),
                    )
                    .saturating_add(
                        group
                            .pending_domain_loss_barriers
                            .get(2 * i + 1)
                            .copied()
                            .unwrap_or(0),
                    );
            }
            header.resolved_payout_blocker_count = percolator::V16PodU64::new(blockers);
        }
        header.materialized_portfolio_count =
            percolator::V16PodU64::new(group.materialized_portfolio_count);
        header.stale_certificate_count = percolator::V16PodU64::new(group.stale_certificate_count);
        header.b_stale_account_count = percolator::V16PodU64::new(group.b_stale_account_count);
        header.negative_pnl_account_count =
            percolator::V16PodU64::new(group.negative_pnl_account_count);
        header.risk_epoch = percolator::V16PodU64::new(group.risk_epoch);
        header.asset_set_epoch = percolator::V16PodU64::new(group.asset_set_epoch);
        header.asset_activation_count = percolator::V16PodU64::new(group.asset_activation_count);
        header.last_asset_activation_slot =
            percolator::V16PodU64::new(group.last_asset_activation_slot);
        header.next_market_id = percolator::V16PodU64::new(group.next_market_id);
        header.oracle_epoch = percolator::V16PodU64::new(group.oracle_epoch);
        header.funding_epoch = percolator::V16PodU64::new(group.funding_epoch);
        header.slot_last = percolator::V16PodU64::new(group.slot_last);
        header.current_slot = percolator::V16PodU64::new(group.current_slot);
        header.bankruptcy_hlock_active = encode_bool_for_account(group.bankruptcy_hlock_active);
        header.threshold_stress_active = encode_bool_for_account(group.threshold_stress_active);
        header.loss_stale_active = encode_bool_for_account(group.loss_stale_active);
        header.recovery_reason =
            percolator::V16OptionalRecoveryReasonAccount::from_runtime(group.recovery_reason);
        header.mode = encode_market_mode_for_account(group.mode);
        header.resolved_slot = percolator::V16PodU64::new(group.resolved_slot);
        header.payout_snapshot = percolator::V16PodU128::new(group.payout_snapshot);
        header.payout_snapshot_pnl_pos_tot =
            percolator::V16PodU128::new(group.payout_snapshot_pnl_pos_tot);
        header.payout_snapshot_captured = encode_bool_for_account(group.payout_snapshot_captured);
        header.resolved_payout_ledger =
            percolator::ResolvedPayoutLedgerV16Account::from_runtime(&group.resolved_payout_ledger);
        let mut i = 0;
        let n = group.config.max_market_slots as usize;
        if group.assets.len() < n {
            return Err(ProgramError::InvalidAccountData);
        }
        while i < n {
            let (long_domain, short_domain) =
                v16_domain_pair_for_asset_index(i).map_err(map_account_wire_error)?;
            let mut slot = *asset_slot_wire(data, i)?;
            slot.asset = percolator::AssetStateV16Account::from_runtime(&group.assets[i]);
            slot.insurance_domain_budget_long =
                percolator::V16PodU128::new(group.insurance_domain_budget[long_domain]);
            slot.insurance_domain_budget_short =
                percolator::V16PodU128::new(group.insurance_domain_budget[short_domain]);
            slot.insurance_domain_spent_long =
                percolator::V16PodU128::new(group.insurance_domain_spent[long_domain]);
            slot.insurance_domain_spent_short =
                percolator::V16PodU128::new(group.insurance_domain_spent[short_domain]);
            slot.pending_domain_loss_barrier_long =
                percolator::V16PodU64::new(group.pending_domain_loss_barriers[long_domain]);
            slot.pending_domain_loss_barrier_short =
                percolator::V16PodU64::new(group.pending_domain_loss_barriers[short_domain]);
            slot.source_credit_long = percolator::SourceCreditStateV16Account::from_runtime(
                &group.source_credit[long_domain],
            );
            slot.source_credit_short = percolator::SourceCreditStateV16Account::from_runtime(
                &group.source_credit[short_domain],
            );
            slot.backing_long = percolator::BackingBucketV16Account::from_runtime(
                &group.source_backing_buckets[long_domain],
            );
            slot.backing_short = percolator::BackingBucketV16Account::from_runtime(
                &group.source_backing_buckets[short_domain],
            );
            slot.insurance_reservation_long =
                percolator::InsuranceCreditReservationV16Account::from_runtime(
                    &group.insurance_credit_reservations[long_domain],
                );
            slot.insurance_reservation_short =
                percolator::InsuranceCreditReservationV16Account::from_runtime(
                    &group.insurance_credit_reservations[short_domain],
                );
            *asset_slot_wire_mut(data, i)? = slot;
            i += 1;
        }
        Ok(())
    }

    #[inline]
    #[cfg(not(target_os = "solana"))]
    fn decode_bool(v: u8) -> Result<bool, ProgramError> {
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    #[cfg(not(target_os = "solana"))]
    pub fn empty_portfolio_boxed(
        header: ProvenanceHeaderV16,
        last_fee_slot: u64,
        source_domain_count: usize,
    ) -> Result<Box<PortfolioAccountV16>, ProgramError> {
        let mut source_claim_market_id = Vec::with_capacity(source_domain_count);
        let mut source_claim_bound_num = Vec::with_capacity(source_domain_count);
        let mut source_claim_liened_num = Vec::with_capacity(source_domain_count);
        let mut source_claim_counterparty_liened_num = Vec::with_capacity(source_domain_count);
        let mut source_claim_insurance_liened_num = Vec::with_capacity(source_domain_count);
        let mut source_lien_effective_reserved = Vec::with_capacity(source_domain_count);
        let mut source_lien_counterparty_backing_num = Vec::with_capacity(source_domain_count);
        let mut source_lien_insurance_backing_num = Vec::with_capacity(source_domain_count);
        let mut source_lien_fee_last_slot = Vec::with_capacity(source_domain_count);
        let mut source_claim_impaired_num = Vec::with_capacity(source_domain_count);
        let mut source_lien_impaired_effective_reserved = Vec::with_capacity(source_domain_count);
        let mut source_lien_capital_at_risk_fee_revenue = Vec::with_capacity(source_domain_count);
        let mut source_lien_impaired_capital_at_risk_fee_revenue =
            Vec::with_capacity(source_domain_count);
        let mut d = 0usize;
        while d < source_domain_count {
            source_claim_market_id.push(0);
            source_claim_bound_num.push(0);
            source_claim_liened_num.push(0);
            source_claim_counterparty_liened_num.push(0);
            source_claim_insurance_liened_num.push(0);
            source_lien_effective_reserved.push(0);
            source_lien_counterparty_backing_num.push(0);
            source_lien_insurance_backing_num.push(0);
            source_lien_fee_last_slot.push(0);
            source_claim_impaired_num.push(0);
            source_lien_impaired_effective_reserved.push(0);
            source_lien_capital_at_risk_fee_revenue.push(0);
            source_lien_impaired_capital_at_risk_fee_revenue.push(0);
            d += 1;
        }

        let mut boxed = Box::<PortfolioAccountV16>::new_uninit();
        let ptr = boxed.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*ptr).provenance_header).write(header);
            core::ptr::addr_of_mut!((*ptr).owner).write(header.owner);
            core::ptr::addr_of_mut!((*ptr).capital).write(0);
            core::ptr::addr_of_mut!((*ptr).pnl).write(0);
            core::ptr::addr_of_mut!((*ptr).reserved_pnl).write(0);
            core::ptr::addr_of_mut!((*ptr).residual_crystallized_loss_atoms_total).write(0);
            core::ptr::addr_of_mut!((*ptr).residual_spent_principal_atoms_total).write(0);
            core::ptr::addr_of_mut!((*ptr).residual_received_atoms_total).write(0);
            core::ptr::addr_of_mut!((*ptr).source_claim_market_id).write(source_claim_market_id);
            core::ptr::addr_of_mut!((*ptr).source_claim_bound_num).write(source_claim_bound_num);
            core::ptr::addr_of_mut!((*ptr).source_claim_liened_num).write(source_claim_liened_num);
            core::ptr::addr_of_mut!((*ptr).source_claim_counterparty_liened_num)
                .write(source_claim_counterparty_liened_num);
            core::ptr::addr_of_mut!((*ptr).source_claim_insurance_liened_num)
                .write(source_claim_insurance_liened_num);
            core::ptr::addr_of_mut!((*ptr).source_lien_effective_reserved)
                .write(source_lien_effective_reserved);
            core::ptr::addr_of_mut!((*ptr).source_lien_counterparty_backing_num)
                .write(source_lien_counterparty_backing_num);
            core::ptr::addr_of_mut!((*ptr).source_lien_insurance_backing_num)
                .write(source_lien_insurance_backing_num);
            core::ptr::addr_of_mut!((*ptr).source_lien_fee_last_slot)
                .write(source_lien_fee_last_slot);
            core::ptr::addr_of_mut!((*ptr).source_claim_impaired_num)
                .write(source_claim_impaired_num);
            core::ptr::addr_of_mut!((*ptr).source_lien_impaired_effective_reserved)
                .write(source_lien_impaired_effective_reserved);
            core::ptr::addr_of_mut!((*ptr).source_lien_capital_at_risk_fee_revenue)
                .write(source_lien_capital_at_risk_fee_revenue);
            core::ptr::addr_of_mut!((*ptr).source_lien_impaired_capital_at_risk_fee_revenue)
                .write(source_lien_impaired_capital_at_risk_fee_revenue);
            core::ptr::addr_of_mut!((*ptr).fee_credits).write(0);
            core::ptr::addr_of_mut!((*ptr).cancel_deposit_escrow).write(0);
            core::ptr::addr_of_mut!((*ptr).last_fee_slot).write(last_fee_slot);
            core::ptr::addr_of_mut!((*ptr).active_bitmap).write(percolator::active_bitmap_empty());
            core::ptr::addr_of_mut!((*ptr).legs)
                .write([PortfolioLegV16::EMPTY; V16_MAX_PORTFOLIO_ASSETS_N]);
            core::ptr::addr_of_mut!((*ptr).health_cert).write(HealthCertV16 {
                certified_equity: 0,
                certified_initial_req: 0,
                certified_maintenance_req: 0,
                certified_liq_deficit: 0,
                certified_worst_case_loss: 0,
                cert_oracle_epoch: 0,
                cert_funding_epoch: 0,
                cert_risk_epoch: 0,
                cert_asset_set_epoch: 0,
                active_bitmap_at_cert: percolator::active_bitmap_empty(),
                valid: false,
            });
            core::ptr::addr_of_mut!((*ptr).stale_state).write(false);
            core::ptr::addr_of_mut!((*ptr).b_stale_state).write(false);
            core::ptr::addr_of_mut!((*ptr).rebalance_lock).write(false);
            core::ptr::addr_of_mut!((*ptr).liquidation_lock).write(false);
            core::ptr::addr_of_mut!((*ptr).close_progress).write(CloseProgressLedgerV16::EMPTY);
            core::ptr::addr_of_mut!((*ptr).resolved_payout_receipt)
                .write(ResolvedPayoutReceiptV16::EMPTY);
            Ok(boxed.assume_init())
        }
    }

    #[cfg(not(target_os = "solana"))]
    fn portfolio_from_wire_boxed(
        data: &[u8],
        source_domain_count: Option<usize>,
    ) -> Result<Box<PortfolioAccountV16>, ProgramError> {
        let wire = portfolio_wire(data)?;
        let header = wire
            .provenance_header
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        // Size the dense runtime to cover all occupied (domain-tagged) sparse slots (or the requested
        // count, whichever is larger). The embedded sparse array is bounded by the position asset cap.
        let mut needed = source_domain_count.unwrap_or(0);
        for slot in wire.source_domains.iter() {
            if slot.is_occupied() {
                needed = needed.max((slot.domain.get() as usize).saturating_add(1));
            }
        }
        let mut account = empty_portfolio_boxed(header, wire.last_fee_slot.get(), needed)?;
        account.owner = wire.owner;
        account.capital = wire.capital.get();
        account.pnl = wire.pnl.get();
        account.reserved_pnl = wire.reserved_pnl.get();
        account.residual_crystallized_loss_atoms_total =
            wire.residual_crystallized_loss_atoms_total.get();
        account.residual_spent_principal_atoms_total =
            wire.residual_spent_principal_atoms_total.get();
        account.residual_received_atoms_total = wire.residual_received_atoms_total.get();
        account.fee_credits = wire.fee_credits.get();
        account.cancel_deposit_escrow = wire.cancel_deposit_escrow.get();
        account.active_bitmap = wire.active_bitmap.map(|v| v.get());
        let mut i = 0usize;
        while i < V16_MAX_PORTFOLIO_ASSETS_N {
            account.legs[i] = wire.legs[i]
                .try_to_runtime()
                .map_err(map_account_wire_error)?;
            i += 1;
        }
        account.health_cert = wire
            .health_cert
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        account.stale_state = decode_bool(wire.stale_state)?;
        account.b_stale_state = decode_bool(wire.b_stale_state)?;
        account.rebalance_lock = decode_bool(wire.rebalance_lock)?;
        account.liquidation_lock = decode_bool(wire.liquidation_lock)?;
        account.close_progress = wire
            .close_progress
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        account.resolved_payout_receipt = wire
            .resolved_payout_receipt
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        for slot in wire.source_domains.iter() {
            if !slot.is_occupied() {
                continue;
            }
            let d = slot.domain.get() as usize;
            account.source_claim_market_id[d] = slot.source_claim_market_id.get();
            account.source_claim_bound_num[d] = slot.source_claim_bound_num.get();
            account.source_claim_liened_num[d] = slot.source_claim_liened_num.get();
            account.source_claim_counterparty_liened_num[d] =
                slot.source_claim_counterparty_liened_num.get();
            account.source_claim_insurance_liened_num[d] =
                slot.source_claim_insurance_liened_num.get();
            account.source_lien_effective_reserved[d] = slot.source_lien_effective_reserved.get();
            account.source_lien_counterparty_backing_num[d] =
                slot.source_lien_counterparty_backing_num.get();
            account.source_lien_insurance_backing_num[d] =
                slot.source_lien_insurance_backing_num.get();
            account.source_lien_fee_last_slot[d] = slot.source_lien_fee_last_slot.get();
            account.source_claim_impaired_num[d] = slot.source_claim_impaired_num.get();
            account.source_lien_impaired_effective_reserved[d] =
                slot.source_lien_impaired_effective_reserved.get();
            account.source_lien_capital_at_risk_fee_revenue[d] =
                slot.source_lien_capital_at_risk_fee_revenue.get();
            account.source_lien_impaired_capital_at_risk_fee_revenue[d] =
                slot.source_lien_impaired_capital_at_risk_fee_revenue.get();
        }
        Ok(account)
    }

    #[cfg(not(target_os = "solana"))]
    fn write_portfolio_wire(
        data: &mut [u8],
        account: &PortfolioAccountV16,
    ) -> Result<(), ProgramError> {
        let account_domain_count = account.source_domain_capacity();
        let wire = portfolio_wire_mut(data)?;
        wire.provenance_header =
            percolator::ProvenanceHeaderV16Account::from_runtime(&account.provenance_header);
        wire.owner = account.owner;
        wire.capital = percolator::V16PodU128::new(account.capital);
        wire.pnl = percolator::V16PodI128::new(account.pnl);
        wire.reserved_pnl = percolator::V16PodU128::new(account.reserved_pnl);
        wire.residual_crystallized_loss_atoms_total =
            percolator::V16PodU128::new(account.residual_crystallized_loss_atoms_total);
        wire.residual_spent_principal_atoms_total =
            percolator::V16PodU128::new(account.residual_spent_principal_atoms_total);
        wire.residual_received_atoms_total =
            percolator::V16PodU128::new(account.residual_received_atoms_total);
        wire.fee_credits = percolator::V16PodI128::new(account.fee_credits);
        wire.cancel_deposit_escrow = percolator::V16PodU128::new(account.cancel_deposit_escrow);
        wire.last_fee_slot = percolator::V16PodU64::new(account.last_fee_slot);
        wire.active_bitmap = account.active_bitmap.map(percolator::V16PodU64::new);
        let mut i = 0usize;
        while i < V16_MAX_PORTFOLIO_ASSETS_N {
            wire.legs[i] = percolator::PortfolioLegV16Account::from_runtime(&account.legs[i]);
            i += 1;
        }
        wire.health_cert = percolator::HealthCertV16Account::from_runtime(&account.health_cert);
        wire.stale_state = encode_bool_for_account(account.stale_state);
        wire.b_stale_state = encode_bool_for_account(account.b_stale_state);
        wire.rebalance_lock = encode_bool_for_account(account.rebalance_lock);
        wire.liquidation_lock = encode_bool_for_account(account.liquidation_lock);
        wire.close_progress =
            percolator::CloseProgressLedgerV16Account::from_runtime(&account.close_progress);
        wire.resolved_payout_receipt = percolator::ResolvedPayoutReceiptV16Account::from_runtime(
            &account.resolved_payout_receipt,
        );
        // Source-domains are a fixed sparse array embedded in the wire header. Clear all slots, then
        // compact the non-empty runtime domains (dense, indexed by domain) into slots, tagging each
        // with its domain index. Bounded by PORTFOLIO_SOURCE_DOMAIN_CAP, independent of N.
        for slot in wire.source_domains.iter_mut() {
            *slot = PortfolioSourceDomainV16Account::default();
        }
        let mut next_slot = 0usize;
        let mut d = 0usize;
        while d < account_domain_count {
            let entry = PortfolioSourceDomainV16Account {
                domain: percolator::V16PodU32::new(
                    u32::try_from(d).map_err(|_| PercolatorError::InvalidAccountLen)?,
                ),
                source_claim_market_id: percolator::V16PodU64::new(
                    account.source_claim_market_id[d],
                ),
                source_claim_bound_num: percolator::V16PodU128::new(
                    account.source_claim_bound_num[d],
                ),
                source_claim_liened_num: percolator::V16PodU128::new(
                    account.source_claim_liened_num[d],
                ),
                source_claim_counterparty_liened_num: percolator::V16PodU128::new(
                    account.source_claim_counterparty_liened_num[d],
                ),
                source_claim_insurance_liened_num: percolator::V16PodU128::new(
                    account.source_claim_insurance_liened_num[d],
                ),
                source_lien_effective_reserved: percolator::V16PodU128::new(
                    account.source_lien_effective_reserved[d],
                ),
                source_lien_counterparty_backing_num: percolator::V16PodU128::new(
                    account.source_lien_counterparty_backing_num[d],
                ),
                source_lien_insurance_backing_num: percolator::V16PodU128::new(
                    account.source_lien_insurance_backing_num[d],
                ),
                source_lien_fee_last_slot: percolator::V16PodU64::new(
                    account.source_lien_fee_last_slot[d],
                ),
                source_claim_impaired_num: percolator::V16PodU128::new(
                    account.source_claim_impaired_num[d],
                ),
                source_lien_impaired_effective_reserved: percolator::V16PodU128::new(
                    account.source_lien_impaired_effective_reserved[d],
                ),
                source_lien_capital_at_risk_fee_revenue: percolator::V16PodU128::new(
                    account.source_lien_capital_at_risk_fee_revenue[d],
                ),
                source_lien_impaired_capital_at_risk_fee_revenue: percolator::V16PodU128::new(
                    account.source_lien_impaired_capital_at_risk_fee_revenue[d],
                ),
            };
            if entry.is_occupied() {
                let slot = wire
                    .source_domains
                    .get_mut(next_slot)
                    .ok_or(PercolatorError::InvalidAccountLen)?;
                *slot = entry;
                next_slot += 1;
            }
            d += 1;
        }
        Ok(())
    }

    pub fn portfolio_view_mut_for_market_slots(
        data: &mut [u8],
        _max_market_slots: usize,
    ) -> Result<PortfolioV16ViewMut<'_>, ProgramError> {
        check_header(data, KIND_PORTFOLIO)?;
        // Source-domains are a fixed sparse array embedded in PortfolioAccountV16Account
        // (covered by PORTFOLIO_STATE_LEN); fixed-size account, no 2N tail.
        let required = HEADER_LEN
            .checked_add(PORTFOLIO_STATE_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        if data.len() < required {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        let portfolio_bytes = data
            .get_mut(HEADER_LEN..required)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let header = bytemuck::try_from_bytes_mut::<PortfolioAccountV16Account>(portfolio_bytes)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        Ok(PortfolioV16ViewMut::new(header))
    }

    pub fn init_market_account_zero_copy(
        data: &mut [u8],
        config: &WrapperConfigV16,
        engine_config: V16Config,
        market_group_id: [u8; 32],
        initial_price: u64,
        init_slot: u64,
    ) -> Result<(), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_MARKET)?;
        write_wrapper_config_to_bytes(data, config)?;
        let base_profile = asset_oracle_profile_from_config(config);
        init_asset_oracle_profiles(data, &base_profile)?;
        let capacity = market_slot_capacity(data)?;
        if capacity > u32::MAX as usize {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        let mut header = MarketGroupV16HeaderAccount::new_dynamic(
            market_group_id,
            engine_config,
            capacity as u32,
            init_slot,
        )
        .map_err(map_account_wire_error)?;
        let configured = header.config.max_market_slots.get() as usize;
        if configured == 0 || configured > capacity {
            return Err(ProgramError::InvalidAccountData);
        }
        let next_market_id = (configured as u64)
            .checked_add(1)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        header.next_market_id = V16PodU64::new(next_market_id);
        *market_header_mut(data)? = header;

        let mut i = 0usize;
        while i < configured {
            let market_id = (i as u64)
                .checked_add(1)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            let mut asset = AssetStateV16::default();
            asset.market_id = market_id;
            asset.raw_oracle_target_price = initial_price;
            asset.effective_price = initial_price;
            asset.fund_px_last = initial_price;
            asset.slot_last = init_slot;
            let mut slot = EngineAssetSlotV16Account::empty_for_market(market_id);
            slot.asset = percolator::AssetStateV16Account::from_runtime(&asset);
            slot.insurance_domain_budget_long = percolator::V16PodU128::new(0);
            slot.insurance_domain_budget_short = percolator::V16PodU128::new(0);
            slot.insurance_domain_spent_long = percolator::V16PodU128::new(0);
            slot.insurance_domain_spent_short = percolator::V16PodU128::new(0);
            *asset_slot_wire_mut(data, i)? = slot;
            i += 1;
        }

        let (_, group) = market_view_mut(data)?;
        group.validate_shape().map_err(map_account_wire_error)?;
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn init_market_account(
        data: &mut [u8],
        config: &WrapperConfigV16,
        group: &MarketGroupV16,
    ) -> Result<(), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_MARKET)?;
        write_wrapper_config_to_bytes(data, config)?;
        let base_profile = asset_oracle_profile_from_config(config);
        init_asset_oracle_profiles(data, &base_profile)?;
        write_market_wire(data, group)?;
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn read_market(data: &[u8]) -> Result<(WrapperConfigV16, MarketGroupV16), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        let config = read_wrapper_config_from_bytes(data)?;
        Ok((config, *market_from_wire_boxed(data, true)?))
    }

    #[cfg(not(target_os = "solana"))]
    pub fn read_market_boxed(
        data: &[u8],
    ) -> Result<(Box<WrapperConfigV16>, Box<MarketGroupV16>), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        let config = read_wrapper_config_boxed_from_bytes(data)?;
        Ok((config, market_from_wire_boxed(data, false)?))
    }

    pub fn read_market_trade_preflight(
        data: &[u8],
        asset_index: usize,
    ) -> Result<(WrapperConfigV16, MarketModeV16, u64, u64, u64), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        let config = read_wrapper_config_from_bytes(data)?;
        let wire = market_header(data)?;
        let engine_config = wire
            .config
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        if asset_index >= engine_config.max_market_slots as usize {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let slot = asset_slot_wire(data, asset_index)?;
        Ok((
            config,
            decode_market_mode(wire.mode)?,
            wire.current_slot.get(),
            slot.asset.effective_price.get(),
            engine_config.max_trading_fee_bps,
        ))
    }

    /// Batch oracle-price read for a multi-leg trade: parse the header/config ONCE, then read each
    /// requested asset's effective price. Avoids the O(N^2) cost of calling
    /// `read_market_trade_preflight` per leg (which re-parses the config every time).
    pub fn read_asset_effective_prices(
        data: &[u8],
        asset_indices: &[u16],
    ) -> Result<(WrapperConfigV16, MarketModeV16, u64, alloc::vec::Vec<u64>), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        let config = read_wrapper_config_from_bytes(data)?;
        let wire = market_header(data)?;
        let engine_config = wire
            .config
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        let mut prices = alloc::vec::Vec::with_capacity(asset_indices.len());
        for &asset_index in asset_indices {
            if asset_index as usize >= engine_config.max_market_slots as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let slot = asset_slot_wire(data, asset_index as usize)?;
            prices.push(slot.asset.effective_price.get());
        }
        Ok((
            config,
            decode_market_mode(wire.mode)?,
            wire.current_slot.get(),
            prices,
        ))
    }

    #[cfg(not(target_os = "solana"))]
    pub fn write_market(
        data: &mut [u8],
        config: &WrapperConfigV16,
        group: &MarketGroupV16,
    ) -> Result<(), ProgramError> {
        if data.len() < MIN_MARKET_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_MARKET)?;
        write_wrapper_config_to_bytes(data, config)?;
        if config.oracle_mode != ORACLE_MODE_MANUAL {
            let base_profile = asset_oracle_profile_from_config(config);
            write_asset_oracle_profile(data, 0, &base_profile)?;
        }
        write_market_wire(data, group)?;
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn init_portfolio_account(
        data: &mut [u8],
        account: &PortfolioAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < PORTFOLIO_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_PORTFOLIO)?;
        write_portfolio_wire(data, account)
    }

    pub fn init_portfolio_account_zero_copy(
        data: &mut [u8],
        market_group_id: [u8; 32],
        portfolio_account_id: [u8; 32],
        owner: [u8; 32],
        last_fee_slot: u64,
        max_market_slots: usize,
    ) -> Result<(), ProgramError> {
        let required = portfolio_account_len_for_market_slots(max_market_slots)?;
        if data.len() < required {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_PORTFOLIO)?;
        let header = ProvenanceHeaderV16::new(market_group_id, portfolio_account_id, owner);
        let wire = portfolio_wire_mut(data)?;
        wire.provenance_header = percolator::ProvenanceHeaderV16Account::from_runtime(&header);
        wire.owner = owner;
        wire.last_fee_slot = percolator::V16PodU64::new(last_fee_slot);
        let empty_leg =
            percolator::PortfolioLegV16Account::from_runtime(&percolator::PortfolioLegV16::EMPTY);
        for leg in wire.legs.iter_mut() {
            *leg = empty_leg;
        }
        Ok(())
    }

    #[cfg(not(target_os = "solana"))]
    pub fn read_portfolio(data: &[u8]) -> Result<PortfolioAccountV16, ProgramError> {
        if data.len() < PORTFOLIO_ENGINE_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_PORTFOLIO)?;
        Ok(*portfolio_from_wire_boxed(data, None)?)
    }

    #[cfg(not(target_os = "solana"))]
    pub fn read_portfolio_boxed(data: &[u8]) -> Result<Box<PortfolioAccountV16>, ProgramError> {
        if data.len() < PORTFOLIO_ENGINE_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_PORTFOLIO)?;
        portfolio_from_wire_boxed(data, None)
    }

    #[cfg(not(target_os = "solana"))]
    pub fn read_portfolio_boxed_for_market_slots(
        data: &[u8],
        max_market_slots: usize,
    ) -> Result<Box<PortfolioAccountV16>, ProgramError> {
        if data.len() < PORTFOLIO_ENGINE_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_PORTFOLIO)?;
        let domains = v16_domain_count_for_market_slots(
            u32::try_from(max_market_slots).map_err(|_| PercolatorError::InvalidAccountLen)?,
        )
        .map_err(map_account_wire_error)?;
        portfolio_from_wire_boxed(data, Some(domains))
    }

    pub fn read_portfolio_owner_preflight(
        data: &[u8],
    ) -> Result<(ProvenanceHeaderV16, [u8; 32]), ProgramError> {
        if data.len() < PORTFOLIO_ENGINE_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_PORTFOLIO)?;
        let wire = portfolio_wire(data)?;
        let header = wire
            .provenance_header
            .try_to_runtime()
            .map_err(map_account_wire_error)?;
        if header.owner != wire.owner {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok((header, wire.owner))
    }

    #[cfg(not(target_os = "solana"))]
    pub fn write_portfolio(
        data: &mut [u8],
        account: &PortfolioAccountV16,
    ) -> Result<(), ProgramError> {
        if data.len() < PORTFOLIO_ENGINE_ACCOUNT_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_PORTFOLIO)?;
        write_portfolio_wire(data, account)
    }

    pub const fn alignment_note() -> usize {
        1
    }

    pub const fn wrapper_config_len_for_test() -> usize {
        WRAPPER_CONFIG_LEN
    }

    // ── Fork LP Vault state types (v17 re-expression) ─────────────────────
    use crate::constants::{
        KIND_LP_REDEMPTION, KIND_LP_VAULT_REGISTRY, KIND_NFT_REGISTRY, LP_ESCROW_SEED,
        LP_VAULT_MINT_SEED, LP_VAULT_REGISTRY_SEED,
        LP_VAULT_VERSION, NFT_REGISTRY_SEED, NFT_REGISTRY_VERSION,
    };

    /// LP Vault registry account. Stored at `["lp_vault", market_group]` PDA.
    /// Size: 160 bytes. Layout is alignment-safe (#[repr(C)] Pod requires no padding).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct LpVaultRegistryV16 {
        pub market_group: [u8; 32],                // 0..32
        pub lp_mint: [u8; 32],                     // 32..64
        pub total_lp_shares_outstanding: u128,     // 64..80
        pub insurance_fee_snapshot_atoms: u128,    // 80..96
        pub fee_distribution_total_atoms: u128,    // 96..112
        pub epoch: u64,                            // 112..120
        pub redemption_cooldown_slots: u64,        // 120..128
        pub fee_share_bps: u16,                    // 128..130
        pub oi_reservation_threshold_bps: u16,     // 130..132
        pub domain: u16,                           // 132..134
        pub paused: u8,                            // 134
        pub version: u8,                           // 135
        pub bump: u8,                              // 136
        pub mint_bump: u8,                         // 137
        pub _padding: [u8; 6],                     // 138..144
        pub _reserved: [u8; 16],                   // 144..160
    }
    const _: () = assert!(core::mem::size_of::<LpVaultRegistryV16>() == 160);

    pub const fn lp_vault_registry_account_len() -> usize {
        HEADER_LEN + core::mem::size_of::<LpVaultRegistryV16>()
    }

    pub fn init_lp_vault_registry(
        data: &mut [u8],
        registry: &LpVaultRegistryV16,
    ) -> Result<(), ProgramError> {
        if data.len() < lp_vault_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        // Validate fields before writing — defense-in-depth; the handler also
        // validates, but the state layer must be self-protecting.
        if registry.market_group == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        if registry.lp_mint == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        if registry.fee_share_bps > 10_000 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if registry.version != LP_VAULT_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        if registry.paused > 1 {
            return Err(ProgramError::InvalidAccountData);
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_LP_VAULT_REGISTRY)?;
        data.get_mut(HEADER_LEN..lp_vault_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(registry));
        Ok(())
    }

    pub fn read_lp_vault_registry(
        data: &[u8],
    ) -> Result<LpVaultRegistryV16, ProgramError> {
        if data.len() < lp_vault_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_LP_VAULT_REGISTRY)?;
        let bytes = data
            .get(HEADER_LEN..lp_vault_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let reg: LpVaultRegistryV16 = bytemuck::pod_read_unaligned(bytes);
        if reg.version != LP_VAULT_VERSION || reg.market_group == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(reg)
    }

    pub fn write_lp_vault_registry(
        data: &mut [u8],
        registry: &LpVaultRegistryV16,
    ) -> Result<(), ProgramError> {
        if data.len() < lp_vault_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_LP_VAULT_REGISTRY)?;
        data.get_mut(HEADER_LEN..lp_vault_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(registry));
        Ok(())
    }

    /// LP Redemption request account. Stored at `["lp_redemption", registry, redeemer]` PDA.
    /// Size: 96 bytes.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct LpRedemptionV16 {
        pub registry: [u8; 32],   // 0..32
        pub redeemer: [u8; 32],   // 32..64
        pub shares: u128,         // 64..80
        pub request_slot: u64,    // 80..88
        pub version: u8,          // 88
        pub bump: u8,             // 89
        pub _padding: [u8; 6],    // 90..96
    }
    const _: () = assert!(core::mem::size_of::<LpRedemptionV16>() == 96);

    pub const fn lp_redemption_account_len() -> usize {
        HEADER_LEN + core::mem::size_of::<LpRedemptionV16>()
    }

    pub fn init_lp_redemption(
        data: &mut [u8],
        redemption: &LpRedemptionV16,
    ) -> Result<(), ProgramError> {
        if data.len() < lp_redemption_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        // Validate non-zero pubkey fields — defense-in-depth.
        if redemption.registry == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        if redemption.redeemer == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_LP_REDEMPTION)?;
        data.get_mut(HEADER_LEN..lp_redemption_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(redemption));
        Ok(())
    }

    pub fn read_lp_redemption(data: &[u8]) -> Result<LpRedemptionV16, ProgramError> {
        if data.len() < lp_redemption_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_LP_REDEMPTION)?;
        let bytes = data
            .get(HEADER_LEN..lp_redemption_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        Ok(bytemuck::pod_read_unaligned(bytes))
    }

    pub fn write_lp_redemption(
        data: &mut [u8],
        redemption: &LpRedemptionV16,
    ) -> Result<(), ProgramError> {
        if data.len() < lp_redemption_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_LP_REDEMPTION)?;
        data.get_mut(HEADER_LEN..lp_redemption_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(redemption));
        Ok(())
    }

    /// PDA derive helpers for LP vault accounts.
    pub fn derive_lp_vault_registry(
        program_id: &solana_program::pubkey::Pubkey,
        market_group: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[LP_VAULT_REGISTRY_SEED, market_group.as_ref()],
            program_id,
        )
    }

    pub fn derive_lp_vault_mint(
        program_id: &solana_program::pubkey::Pubkey,
        market_group: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[LP_VAULT_MINT_SEED, market_group.as_ref()],
            program_id,
        )
    }

    pub fn derive_lp_redemption(
        program_id: &solana_program::pubkey::Pubkey,
        registry: &solana_program::pubkey::Pubkey,
        redeemer: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[
                crate::constants::LP_REDEMPTION_SEED,
                registry.as_ref(),
                redeemer.as_ref(),
            ],
            program_id,
        )
    }

    /// LP Vault backing-domain ledger PDA: `["lp_backing_ledger", market, domain_le]`.
    pub fn derive_lp_backing_ledger(
        program_id: &solana_program::pubkey::Pubkey,
        market_group: &solana_program::pubkey::Pubkey,
        domain: u16,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[
                crate::constants::LP_BACKING_LEDGER_SEED,
                market_group.as_ref(),
                &domain.to_le_bytes(),
            ],
            program_id,
        )
    }

    /// Consume an LpRedemption PDA by zeroing its header magic — the
    /// DOUBLE-EXECUTE REPLAY GUARD. After this, `read_lp_redemption`
    /// returns `NotInitialized` on any replayed `ExecuteRedemption`.
    pub fn consume_lp_redemption(data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < HEADER_LEN {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_LP_REDEMPTION)?;
        // Zero the magic to invalidate on replay.
        for b in data[0..8].iter_mut() {
            *b = 0;
        }
        Ok(())
    }

    pub fn derive_lp_escrow(
        program_id: &solana_program::pubkey::Pubkey,
        market_group: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[LP_ESCROW_SEED, market_group.as_ref()],
            program_id,
        )
    }

    /// Compute LP shares for a deposit: round DOWN (Note 1 — reject if 0).
    /// shares = (amount * total_shares) / nav_atoms. If nav == 0, shares = amount.
    pub fn lp_shares_for_deposit(
        amount: u128,
        total_shares: u128,
        nav_atoms: u128,
    ) -> Result<u128, ProgramError> {
        let shares = if total_shares == 0 || nav_atoms == 0 {
            // Bootstrap: 1 share per atom.
            amount
        } else {
            let num = amount
                .checked_mul(total_shares)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            num / nav_atoms
        };
        Ok(shares)
    }

    /// Compute atoms redeemable for `shares`: round DOWN (conservative; protects vault).
    /// atoms = (shares * nav_atoms) / total_shares. Returns 0 if total_shares == 0.
    pub fn lp_atoms_for_shares(
        shares: u128,
        total_shares: u128,
        nav_atoms: u128,
    ) -> Result<u128, ProgramError> {
        if total_shares == 0 {
            return Ok(0);
        }
        let num = shares
            .checked_mul(nav_atoms)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(num / total_shares)
    }

    // ── Fork NFT Registry state types (v17 re-expression) ─────────────────

    /// Per-market NFT program-id registry. Stored at `["nft_registry", market_group]` PDA.
    /// Size: 72 bytes.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
    pub struct NftRegistryV16 {
        pub market_group: [u8; 32],   // 0..32
        pub nft_program_id: [u8; 32], // 32..64
        pub version: u8,              // 64
        pub bump: u8,                 // 65
        pub _padding: [u8; 6],        // 66..72
    }
    const _: () = assert!(core::mem::size_of::<NftRegistryV16>() == 72);

    pub const fn nft_registry_account_len() -> usize {
        HEADER_LEN + core::mem::size_of::<NftRegistryV16>()
    }

    pub fn init_nft_registry(
        data: &mut [u8],
        registry: &NftRegistryV16,
    ) -> Result<(), ProgramError> {
        if data.len() < nft_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        if is_initialized(data) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        for b in data.iter_mut() {
            *b = 0;
        }
        write_header(data, KIND_NFT_REGISTRY)?;
        data.get_mut(HEADER_LEN..nft_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(registry));
        Ok(())
    }

    pub fn read_nft_registry(data: &[u8]) -> Result<NftRegistryV16, ProgramError> {
        if data.len() < nft_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_NFT_REGISTRY)?;
        let bytes = data
            .get(HEADER_LEN..nft_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let reg: NftRegistryV16 = bytemuck::pod_read_unaligned(bytes);
        if reg.version != NFT_REGISTRY_VERSION
            || reg.market_group == [0u8; 32]
            || reg.nft_program_id == [0u8; 32]
            || reg._padding != [0u8; 6]
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(reg)
    }

    pub fn write_nft_registry(
        data: &mut [u8],
        registry: &NftRegistryV16,
    ) -> Result<(), ProgramError> {
        if data.len() < nft_registry_account_len() {
            return Err(PercolatorError::InvalidAccountLen.into());
        }
        check_header(data, KIND_NFT_REGISTRY)?;
        data.get_mut(HEADER_LEN..nft_registry_account_len())
            .ok_or(PercolatorError::InvalidAccountLen)?
            .copy_from_slice(bytemuck::bytes_of(registry));
        Ok(())
    }

    pub fn derive_nft_registry(
        program_id: &solana_program::pubkey::Pubkey,
        market_group: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[NFT_REGISTRY_SEED, market_group.as_ref()],
            program_id,
        )
    }

    /// Derive the NFT program's mint-authority PDA (shared seed contract with percolator-nft).
    pub fn derive_nft_mint_authority(
        nft_program_id: &solana_program::pubkey::Pubkey,
    ) -> (solana_program::pubkey::Pubkey, u8) {
        solana_program::pubkey::Pubkey::find_program_address(
            &[crate::constants::NFT_MINT_AUTHORITY_SEED],
            nft_program_id,
        )
    }

}

pub mod ix {
    use alloc::vec::Vec;
    use solana_program::program_error::ProgramError;

    /// One leg of an atomic multi-leg batch trade. `size_q` is SIGNED (engine semantics): a
    /// positive size makes the taker (account_a) long that asset, a negative size makes it short,
    /// so a single batch can express a mixed-direction spread (long A / short B) against one LP.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BatchTradeLeg {
        pub asset_index: u16,
        pub size_q: i128,
        pub exec_price: u64,
        pub fee_bps: u64,
    }

    /// One leg of an atomic multi-leg batch routed through an external matcher. `size_q` is the
    /// SIGNED requested size (the matcher returns the actual exec size/price); `limit_price` is a
    /// per-leg bound (0 = no limit) checked against the matcher's exec price.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BatchTradeCpiLeg {
        pub asset_index: u16,
        pub size_q: i128,
        pub fee_bps: u64,
        pub limit_price: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Instruction {
        InitMarket {
            max_portfolio_assets: u16,
            h_min: u64,
            h_max: u64,
            initial_price: u64,
            min_nonzero_mm_req: u128,
            min_nonzero_im_req: u128,
            maintenance_margin_bps: u64,
            initial_margin_bps: u64,
            max_trading_fee_bps: u64,
            trade_fee_base_bps: u64,
            liquidation_fee_bps: u64,
            liquidation_fee_cap: u128,
            min_liquidation_abs: u128,
            max_price_move_bps_per_slot: u64,
            max_accrual_dt_slots: u64,
            max_abs_funding_e9_per_slot: u64,
            min_funding_lifetime_slots: u64,
            max_account_b_settlement_chunks: u64,
            max_bankrupt_close_chunks: u64,
            max_bankrupt_close_lifetime_slots: u64,
            public_b_chunk_atoms: u128,
            maintenance_fee_per_slot: u128,
        },
        InitPortfolio,
        Deposit {
            amount: u128,
        },
        Withdraw {
            amount: u128,
        },
        /// FIX W3 (upstream #206, pairs with engine E3 / upstream #92): liquidation
        /// size and fee are engine-selected (`liquidation_engine_close_request_q` +
        /// config-only `fee_bps`, v16.rs `liquidate_account_not_atomic`) -- the wire
        /// format no longer accepts caller-supplied `close_q`/`fee_bps`, closing the
        /// "min-fee chunking" exploit where a keeper could pick a tiny close_q to
        /// under-pay the liquidation fee while still making forward progress.
        PermissionlessCrank {
            action: u8,
            asset_index: u16,
            now_slot: u64,
            funding_rate_e9: i128,
            recovery_reason: u8,
        },
        TradeNoCpi {
            asset_index: u16,
            size_q: i128,
            exec_price: u64,
            fee_bps: u64,
        },
        TradeCpi {
            asset_index: u16,
            size_q: i128,
            fee_bps: u64,
            limit_price: u64,
        },
        /// Atomic multi-leg batch: apply every leg against one taker/LP pair with a single
        /// end-state initial-margin check (interim legs need not be individually margin-feasible).
        BatchTradeNoCpi {
            legs: Vec<BatchTradeLeg>,
        },
        /// Atomic multi-leg batch routed through an external matcher: one batched matcher CPI fills
        /// every leg against a single LP, then all fills apply with one end-state margin check.
        BatchTradeCpi {
            legs: Vec<BatchTradeCpiLeg>,
        },
        SetMatcherConfig {
            enabled: u8,
        },
        ClosePortfolio,
        TopUpInsurance {
            amount: u128,
        },
        TopUpInsuranceDomain {
            domain: u16,
            amount: u128,
        },
        CloseSlab,
        ResolveMarket,
        TopUpBackingBucket {
            domain: u16,
            amount: u128,
            expiry_slot: u64,
        },
        WithdrawBackingBucket {
            domain: u16,
            amount: u128,
        },
        ConvertReleasedPnl {
            amount: u128,
        },
        CloseResolved {
            fee_rate_per_slot: u128,
        },
        /// Rotate the single market-level authority (`marketauth`). The current `marketauth` must sign;
        /// the non-zero replacement must co-sign. Burning `marketauth` to zero is rejected.
        UpdateAuthority {
            new_pubkey: [u8; 32],
        },
        /// Rotate one of an asset's per-asset authorities. Gated by the asset's own `asset_admin`
        /// (rotates any; only the admin authority itself is burnable) or the current holder of that
        /// authority (self-rotation). Isolated to the given asset_index.
        UpdateAssetAuthority {
            asset_index: u16,
            kind: u8,
            new_pubkey: [u8; 32],
        },
        UpdateLiquidationFeePolicy {
            cranker_share_bps: u16,
        },
        UpdateMaintenanceFeePolicy {
            cranker_share_bps: u16,
        },
        UpdateBackingFeePolicy {
            domain: u16,
            fee_bps: u16,
            insurance_share_bps: u16,
        },
        UpdateTradeFeePolicy {
            trade_fee_base_bps: u64,
        },
        UpdateFeeRedirectPolicy {
            redirect_bps: u16,
        },
        /// #427 — make the insurance-withdrawal rate limit SETTABLE.
        ///
        /// `insurance_withdraw_deposits_only` and `insurance_withdraw_cooldown_slots`
        /// were written in exactly one place each — `: 0,` in the `handle_init_market`
        /// config literal — and both enforcement helpers short-circuit on zero. The
        /// checks added by #385/#386/#396 therefore could not execute in any market
        /// ever created. This instruction is the missing writer.
        UpdateInsuranceWithdrawPolicy {
            deposits_only: u8,
            cooldown_slots: u64,
        },
        UpdateMarketInitFeePolicy {
            min_init_fee: u128,
        },
        WithdrawBackingBucketEarnings {
            domain: u16,
            amount: u128,
        },
        SyncBackingDomainLedger {
            domain: u16,
        },
        SyncInsuranceLedger,
        ConfigurePermissionlessResolve {
            stale_slots: u64,
            force_close_delay_slots: u64,
        },
        ResolveStalePermissionless {
            now_slot: u64,
        },
        ConfigureHybridOracle {
            asset_index: u16,
            now_slot: u64,
            now_unix_ts: i64,
            oracle_leg_count: u8,
            oracle_leg_flags: u8,
            max_staleness_secs: u64,
            hybrid_soft_stale_slots: u64,
            mark_ewma_halflife_slots: u64,
            mark_min_fee: u64,
            invert: u8,
            unit_scale: u32,
            conf_filter_bps: u16,
            oracle_leg_feeds: [[u8; 32]; 3],
        },
        ConfigureEwmaMark {
            asset_index: u16,
            now_slot: u64,
            initial_mark_e6: u64,
            mark_ewma_halflife_slots: u64,
            mark_min_fee: u64,
        },
        PushEwmaMark {
            asset_index: u16,
            now_slot: u64,
            mark_e6: u64,
        },
        ConfigureAuthMark {
            asset_index: u16,
            now_slot: u64,
            initial_mark_e6: u64,
        },
        PushAuthMark {
            asset_index: u16,
            now_slot: u64,
            mark_e6: u64,
        },
        ForceCloseAbandonedAsset {
            asset_index: u16,
            now_slot: u64,
            close_q: u128,
        },
        RestartAssetOracle {
            asset_index: u16,
            now_slot: u64,
            initial_price: u64,
        },
        UpdateAssetLifecycle {
            action: u8,
            asset_index: u16,
            now_slot: u64,
            initial_price: u64,
            insurance_authority: [u8; 32],
            insurance_operator: [u8; 32],
            backing_bucket_authority: [u8; 32],
            oracle_authority: [u8; 32],
        },
        WithdrawInsurance {
            amount: u128,
        },
        WithdrawInsuranceAsset {
            asset_index: u16,
            amount: u128,
        },
        CureAndCancelClose {
            optional_deposit: u128,
        },
        ForfeitRecoveryLeg {
            asset_index: u16,
            b_delta_budget: u128,
        },
        RebalanceReduce {
            asset_index: u16,
            reduce_q: u128,
        },
        FinalizeResetSide {
            asset_index: u16,
            side: u8,
        },
        ClaimResolvedPayoutTopup,
        RefineResolvedUnreceiptedBound {
            decrease_num: u128,
        },
        SyncMaintenanceFee {
            now_slot: u64,
        },
        UpdateBaseUnitMints {
            primary_mint: [u8; 32],
            secondary_mint: [u8; 32],
        },
        SwapSecondaryForPrimary {
            amount: u128,
        },
        // ── Fork LP Vault instructions (tags 74-80, v17 renumber from 65-71) ──
        CreateLpVault {
            fee_share_bps: u16,
            redemption_cooldown_slots: u64,
            oi_reservation_threshold_bps: u16,
            domain: u16,
        },
        DepositToLpVault {
            amount: u128,
            /// Which pot of the vault's asset receives the backing. Must satisfy
            /// `domain / 2 == registry.domain / 2`. Shares are priced off COMBINED
            /// NAV, so the depositor is indifferent to the choice; routing exists
            /// so new money can reach whichever pot the house is drawing on.
            domain: u16,
        },
        /// Move IDLE (fresh, unliened) backing between the two domains of the
        /// vault's asset. spec.md L410 requires refill be source-domain local;
        /// the vault is welded to one domain at creation, so without this the
        /// sibling domain can never be funded. Moves ledger principal in
        /// lockstep so NAV stays in sync with the buckets.
        RebalanceLpVaultBacking {
            from_domain: u16,
            to_domain: u16,
            amount: u128,
        },
        RequestRedeemLpShares {
            shares: u128,
        },
        ExecuteRedemption {
            /// Which pot of the vault's asset the payout is physically drawn
            /// from. NAV and available-principal stay COMBINED across both pots,
            /// so this does not change what the redeemer is owed — only where the
            /// atoms come from. Needed because the money may legitimately sit in
            /// the sibling: that is the entire point of routing deposits there.
            domain: u16,
        },
        LpVaultCrankFees {
            /// Which pot of the vault's asset receives the cranked fees. Must
            /// satisfy `domain / 2 == registry.domain / 2`. Mints no shares, so
            /// the choice cannot dilute; routing exists so fees can become
            /// backing in the pot that actually needs it.
            domain: u16,
        },
        SetLpVaultPaused {
            paused: u8,
        },
        CloseLpVault,
        /// LP Vault — CancelRedemption (tag 81). Reversal of RequestRedeemLpShares:
        /// returns the escrowed LP shares to the recorded redeemer and consumes the
        /// LpRedemption PDA. Redeemer-signed; callable in any market mode.
        CancelRedemption,
        // ── Fork NFT / B-3 instructions (tags 72/73) ──
        TransferPortfolioOwnership {
            new_owner: [u8; 32],
            asset_index: u16,
        },
        SetNftProgramId {
            nft_program_id: [u8; 32],
        },
        /// UnwrapEscrowedPortfolio (tag 82) — release NFT-escrow back to the
        /// burning holder. See `TAG_UNWRAP_ESCROWED_PORTFOLIO`.
        UnwrapEscrowedPortfolio {
            new_owner: [u8; 32],
        },
        /// InitMatcherCtx (tag 83): bootstrap a matcher context by CPIing to the
        /// matcher program with the delegate PDA as signer.
        ///
        /// This is the only way to initialize a matcher context — the delegate PDA
        /// cannot sign a top-level transaction, so the wrapper must sign via
        /// invoke_signed. Must be called after SetMatcherConfig has registered the
        /// (matcher_prog, matcher_ctx, delegate) triple on the LP portfolio.
        ///
        /// Ported verbatim (wire-identical) from the deployed lineage
        /// (percolator-prog@6ca7b97b, "fix(wrapper,v17): InitMatcherCtx (tag 83)")
        /// so the client's existing ~70-byte tag-83 payload keeps decoding exactly
        /// as it does against the live program.
        ///
        /// Accounts: [lp_owner(signer), market_ai, lp_portfolio_ai,
        ///            matcher_ctx(writable), matcher_prog(executable), matcher_delegate]
        InitMatcherCtx {
            kind: u8,
            trading_fee_bps: u32,
            base_spread_bps: u32,
            max_total_bps: u32,
            impact_k_bps: u32,
            liquidity_notional_e6: u128,
            max_fill_abs: u128,
            max_inventory_abs: u128,
            fee_to_insurance_bps: u16,
            skew_spread_mult_bps: u16,
        },
        // ── Protocol-fee program change (tags 84/85) ────────────────────────
        // See ~/v17/PROTOCOL-FEE-DESIGN.md §3. Renumbered 83/84 → 84/85 (2026-07-15)
        // to free tag 83 for the ported InitMatcherCtx, which the deployed wrapper
        // lineage already occupies at that tag (see DECISIONS-LEDGER.md "Pinned
        // deployed revisions").
        /// WithdrawProtocolFee (tag 84) — pays out from the accrued-but-
        /// unwithdrawn protocol claim to an external token account.
        /// `amount == 0` means "withdraw all currently-available capacity".
        /// Signer-gated on `cfg.protocol_fee_authority`.
        WithdrawProtocolFee {
            amount: u128,
        },
        /// SetProtocolFeeAuthority (tag 85) — rotates `protocol_fee_authority`.
        /// Gated on the program's BPF upgrade authority (a new pattern for
        /// this codebase; see `read_program_data_upgrade_authority`), NOT on
        /// `marketauth`/any creator-facing gate.
        SetProtocolFeeAuthority {
            new_authority: [u8; 32],
        },
        /// UpdateFeeSplit (tag 86) — sets the three fee-split shares.
        /// Gated on `marketauth`. Shares must sum to FEE_SHARE_TOTAL_BPS and
        /// satisfy the floors (creator <=45%, LP >=40%, insurance >=15%).
        UpdateFeeSplit {
            creator_share_bps: u16,
            lp_share_bps: u16,
            insurance_share_bps: u16,
        },
        /// WithdrawInsuranceReserveToStake (tag 87) — permissionless. Pushes
        /// the accrued insurance/staker leg into the stake vault, producing
        /// exactly the vault surplus percolator-stake's AccrueFees measures.
        WithdrawInsuranceReserveToStake,
        /// UpdateMaintenanceFeePerSlot (tag 88) — marketauth-gated.
        /// Closes a real defect: the value was an InitMarket constructor
        /// argument with NO setter anywhere in the dispatch table, so it was
        /// permanently frozen per market. Default remains 0; this restores
        /// optionality only and does not enable the maintenance fee.
        ///
        /// The payload is a `u128`, matching the storage type
        /// (`WrapperConfigV16::maintenance_fee_per_slot`) and InitMarket's own
        /// wire encoding. A `u64` payload would leave all but the bottom
        /// ~1.8e19 of the `MAX_PROTOCOL_FEE_ABS` (1e36) valid range
        /// unreachable and would disagree with InitMarket's `read_u128`.
        ///
        /// REACHABILITY: gated on `cfg.marketauth`, which `StakeInitPool`
        /// irreversibly rotates to the stake-pool PDA. On a staked market this
        /// tag is therefore unreachable until a CPI proxy exists.
        UpdateMaintenanceFeePerSlot {
            maintenance_fee_per_slot: u128,
        },
        /// ExpireBackingBucket (tag 89) — advance a LAPSED source-domain
        /// backing bucket out of `Fresh` on a Live market.
        ///
        /// WHY THIS EXISTS. A realized loss reserves capital as counterparty
        /// backing (`reserve_new_capital_backed_loss_for_source_domain_not_atomic`),
        /// which opens the domain's bucket as `Fresh` with
        /// `expiry_slot = current_slot + max(max_accrual_dt_slots, h_max,
        /// max_bankrupt_close_lifetime_slots)`. That expiry is fixed when the
        /// bucket opens and is NEVER extended while the bucket stays `Fresh`
        /// (`fresh_counterparty_backing_expiry_slot` returns the stored expiry
        /// unchanged on a live bucket), so every backed market reaches the
        /// lapse eventually — a longer horizon defers it, it does not avoid it.
        ///
        /// Once `Fresh` has lapsed, the domain is a DEAD END in all three
        /// directions, permanently:
        ///   * settling a gain against it -> `EngineStale` (Custom 19), from
        ///     `validate_source_domain_ledger_current`;
        ///   * reserving a further loss against it -> `EngineLockActive`
        ///     (Custom 21), from `prepare_counterparty_backing_add_delta`'s
        ///     expiry-mismatch arm;
        ///   * `TopUpBackingBucket` to re-fund it -> `EngineLockActive` (21),
        ///     same arm. The bucket cannot even be paid to come back.
        ///
        /// The engine already owns the escape — `expire_source_backing_bucket_not_atomic`
        /// — and uses it itself in `realize_source_backed_claims_for_resolved_close_not_atomic`,
        /// whose comment states that without it a lapsed bucket "would
        /// otherwise return Stale and strand the winner's close". That sweep
        /// only runs on the RESOLVED path; nothing in this wrapper ever reached
        /// the transition on a LIVE market. This tag is that missing call site.
        ///
        /// PERMISSIONLESS BY DESIGN: a bricked market must be recoverable by
        /// any keeper, not only by an authority that may be a cold key or a
        /// stake-pool PDA. It is not an authority hole — the engine refuses the
        /// transition unless the bucket is `Fresh` AND `now_slot >=
        /// expiry_slot`, and `now_slot` here is the runtime `Clock`, never a
        /// caller-supplied value, so no caller can force an early forfeiture.
        ///
        /// Expiry forfeits the lapsed principal to the junior pool. That is the
        /// engine's documented expiry semantics, not a new haircut invented
        /// here: the alternative is the account never settling at all.
        ExpireBackingBucket {
            domain: u16,
        },
        // ── Creator fee claim (2026-07-23 design §3) ────────────────────────
        /// WithdrawCreatorFee (tag 90) — pays the market creator's accrued
        /// trade-fee share out of the vault to an external token account, and
        /// decrements `WrapperConfigV16::creator_fee_claimable_atoms` by
        /// exactly `amount`.
        ///
        /// AUTHORITY: asset 0's `asset_admin`, and ONLY that. It bootstraps to
        /// the asset activator (the creator) and is rotated ONLY by its holder
        /// via `UpdateAssetAuthority`. Crucially, it is the one creator-facing
        /// field the wizard's full create flow leaves alone: `StakeInitPool` +
        /// `BindInsuranceAuthority` rotate `marketauth`, `insurance_authority`
        /// AND `insurance_operator` to program PDAs, so gating on any of those
        /// makes the creator's fees unclaimable on a staked market (no wallet
        /// holds a PDA key — verified on the live staked market 7FBXdrm1…). Do
        /// NOT reuse `verify_domain_withdrawal_preflight`'s check, which accepts
        /// `cfg.marketauth` as an alternate gate: on a staked market that IS the
        /// stake-pool PDA and would hand the creator's revenue to the pool.
        ///
        /// `amount == 0` is REJECTED. It deliberately does NOT mean "withdraw
        /// everything available" the way `WithdrawProtocolFee` (tag 84) reads
        /// it: this instruction's contract is an exact debit of the counter,
        /// and a silent 0-atom transfer is a caller bug, not a claim.
        WithdrawCreatorFee {
            amount: u128,
        },
    }

    impl Instruction {
        pub fn decode(input: &[u8]) -> Result<Self, ProgramError> {
            let (&tag, mut rest) = input
                .split_first()
                .ok_or(ProgramError::InvalidInstructionData)?;
            let ix = match tag {
                0 => Self::InitMarket {
                    max_portfolio_assets: read_u16(&mut rest)?,
                    h_min: read_u64(&mut rest)?,
                    h_max: read_u64(&mut rest)?,
                    initial_price: read_u64(&mut rest)?,
                    min_nonzero_mm_req: read_u128(&mut rest)?,
                    min_nonzero_im_req: read_u128(&mut rest)?,
                    maintenance_margin_bps: read_u64(&mut rest)?,
                    initial_margin_bps: read_u64(&mut rest)?,
                    max_trading_fee_bps: read_u64(&mut rest)?,
                    trade_fee_base_bps: read_u64(&mut rest)?,
                    liquidation_fee_bps: read_u64(&mut rest)?,
                    liquidation_fee_cap: read_u128(&mut rest)?,
                    min_liquidation_abs: read_u128(&mut rest)?,
                    max_price_move_bps_per_slot: read_u64(&mut rest)?,
                    max_accrual_dt_slots: read_u64(&mut rest)?,
                    max_abs_funding_e9_per_slot: read_u64(&mut rest)?,
                    min_funding_lifetime_slots: read_u64(&mut rest)?,
                    max_account_b_settlement_chunks: read_u64(&mut rest)?,
                    max_bankrupt_close_chunks: read_u64(&mut rest)?,
                    max_bankrupt_close_lifetime_slots: read_u64(&mut rest)?,
                    public_b_chunk_atoms: read_u128(&mut rest)?,
                    maintenance_fee_per_slot: read_u128(&mut rest)?,
                },
                1 => Self::InitPortfolio,
                3 => Self::Deposit {
                    amount: read_u128(&mut rest)?,
                },
                4 => Self::Withdraw {
                    amount: read_u128(&mut rest)?,
                },
                5 => Self::PermissionlessCrank {
                    action: read_u8(&mut rest)?,
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    funding_rate_e9: read_i128(&mut rest)?,
                    recovery_reason: read_u8(&mut rest)?,
                },
                6 => Self::TradeNoCpi {
                    asset_index: read_u16(&mut rest)?,
                    size_q: read_i128(&mut rest)?,
                    exec_price: read_u64(&mut rest)?,
                    fee_bps: read_u64(&mut rest)?,
                },
                10 => Self::TradeCpi {
                    asset_index: read_u16(&mut rest)?,
                    size_q: read_i128(&mut rest)?,
                    fee_bps: read_u64(&mut rest)?,
                    limit_price: read_u64(&mut rest)?,
                },
                66 => {
                    let n = read_u8(&mut rest)? as usize;
                    let mut legs = Vec::with_capacity(n);
                    for _ in 0..n {
                        legs.push(BatchTradeLeg {
                            asset_index: read_u16(&mut rest)?,
                            size_q: read_i128(&mut rest)?,
                            exec_price: read_u64(&mut rest)?,
                            fee_bps: read_u64(&mut rest)?,
                        });
                    }
                    Self::BatchTradeNoCpi { legs }
                }
                67 => {
                    let n = read_u8(&mut rest)? as usize;
                    let mut legs = Vec::with_capacity(n);
                    for _ in 0..n {
                        legs.push(BatchTradeCpiLeg {
                            asset_index: read_u16(&mut rest)?,
                            size_q: read_i128(&mut rest)?,
                            fee_bps: read_u64(&mut rest)?,
                            limit_price: read_u64(&mut rest)?,
                        });
                    }
                    Self::BatchTradeCpi { legs }
                }
                68 => Self::SetMatcherConfig {
                    enabled: read_u8(&mut rest)?,
                },
                8 => Self::ClosePortfolio,
                9 => Self::TopUpInsurance {
                    amount: read_u128(&mut rest)?,
                },
                56 => Self::TopUpInsuranceDomain {
                    domain: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                },
                13 => Self::CloseSlab,
                19 => Self::ResolveMarket,
                24 => Self::TopUpBackingBucket {
                    domain: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                    expiry_slot: read_u64(&mut rest)?,
                },
                50 => Self::WithdrawBackingBucket {
                    domain: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                },
                28 => Self::ConvertReleasedPnl {
                    amount: read_u128(&mut rest)?,
                },
                30 => Self::CloseResolved {
                    fee_rate_per_slot: read_u128(&mut rest)?,
                },
                32 => Self::UpdateAuthority {
                    new_pubkey: read_bytes32(&mut rest)?,
                },
                65 => Self::UpdateAssetAuthority {
                    asset_index: read_u16(&mut rest)?,
                    kind: read_u8(&mut rest)?,
                    new_pubkey: read_bytes32(&mut rest)?,
                },
                37 => Self::UpdateLiquidationFeePolicy {
                    cranker_share_bps: read_u16(&mut rest)?,
                },
                49 => Self::UpdateMaintenanceFeePolicy {
                    cranker_share_bps: read_u16(&mut rest)?,
                },
                51 => Self::UpdateBackingFeePolicy {
                    domain: read_u16(&mut rest)?,
                    fee_bps: read_u16(&mut rest)?,
                    insurance_share_bps: read_u16(&mut rest)?,
                },
                55 => Self::UpdateTradeFeePolicy {
                    trade_fee_base_bps: read_u64(&mut rest)?,
                },
                58 => Self::UpdateFeeRedirectPolicy {
                    redirect_bps: read_u16(&mut rest)?,
                },
                92 => Self::UpdateInsuranceWithdrawPolicy {
                    deposits_only: read_u8(&mut rest)?,
                    cooldown_slots: read_u64(&mut rest)?,
                },
                59 => Self::UpdateMarketInitFeePolicy {
                    min_init_fee: read_u128(&mut rest)?,
                },
                60 => Self::UpdateBaseUnitMints {
                    primary_mint: read_bytes32(&mut rest)?,
                    secondary_mint: read_bytes32(&mut rest)?,
                },
                61 => Self::SwapSecondaryForPrimary {
                    amount: read_u128(&mut rest)?,
                },
                62 => Self::ConfigureAuthMark {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    initial_mark_e6: read_u64(&mut rest)?,
                },
                63 => Self::PushAuthMark {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    mark_e6: read_u64(&mut rest)?,
                },
                64 => Self::ForceCloseAbandonedAsset {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    close_q: read_u128(&mut rest)?,
                },
                69 => Self::RestartAssetOracle {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    initial_price: read_u64(&mut rest)?,
                },
                52 => Self::WithdrawBackingBucketEarnings {
                    domain: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                },
                53 => Self::SyncBackingDomainLedger {
                    domain: read_u16(&mut rest)?,
                },
                54 => Self::SyncInsuranceLedger,
                38 => Self::ConfigurePermissionlessResolve {
                    stale_slots: read_u64(&mut rest)?,
                    force_close_delay_slots: read_u64(&mut rest)?,
                },
                39 => Self::ResolveStalePermissionless {
                    now_slot: read_u64(&mut rest)?,
                },
                34 => Self::ConfigureHybridOracle {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    now_unix_ts: read_i64(&mut rest)?,
                    oracle_leg_count: read_u8(&mut rest)?,
                    oracle_leg_flags: read_u8(&mut rest)?,
                    max_staleness_secs: read_u64(&mut rest)?,
                    hybrid_soft_stale_slots: read_u64(&mut rest)?,
                    mark_ewma_halflife_slots: read_u64(&mut rest)?,
                    mark_min_fee: read_u64(&mut rest)?,
                    invert: read_u8(&mut rest)?,
                    unit_scale: read_u32(&mut rest)?,
                    conf_filter_bps: read_u16(&mut rest)?,
                    oracle_leg_feeds: [
                        read_bytes32(&mut rest)?,
                        read_bytes32(&mut rest)?,
                        read_bytes32(&mut rest)?,
                    ],
                },
                35 => Self::ConfigureEwmaMark {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    initial_mark_e6: read_u64(&mut rest)?,
                    mark_ewma_halflife_slots: read_u64(&mut rest)?,
                    mark_min_fee: read_u64(&mut rest)?,
                },
                36 => Self::PushEwmaMark {
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    mark_e6: read_u64(&mut rest)?,
                },
                40 => Self::UpdateAssetLifecycle {
                    action: read_u8(&mut rest)?,
                    asset_index: read_u16(&mut rest)?,
                    now_slot: read_u64(&mut rest)?,
                    initial_price: read_u64(&mut rest)?,
                    insurance_authority: read_bytes32(&mut rest)?,
                    insurance_operator: read_bytes32(&mut rest)?,
                    backing_bucket_authority: read_bytes32(&mut rest)?,
                    oracle_authority: read_bytes32(&mut rest)?,
                },
                41 => Self::WithdrawInsurance {
                    amount: read_u128(&mut rest)?,
                },
                57 => Self::WithdrawInsuranceAsset {
                    asset_index: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                },
                42 => Self::CureAndCancelClose {
                    optional_deposit: read_u128(&mut rest)?,
                },
                43 => Self::ForfeitRecoveryLeg {
                    asset_index: read_u16(&mut rest)?,
                    b_delta_budget: read_u128(&mut rest)?,
                },
                44 => Self::RebalanceReduce {
                    asset_index: read_u16(&mut rest)?,
                    reduce_q: read_u128(&mut rest)?,
                },
                45 => Self::FinalizeResetSide {
                    asset_index: read_u16(&mut rest)?,
                    side: read_u8(&mut rest)?,
                },
                46 => Self::ClaimResolvedPayoutTopup,
                47 => Self::RefineResolvedUnreceiptedBound {
                    decrease_num: read_u128(&mut rest)?,
                },
                48 => Self::SyncMaintenanceFee {
                    now_slot: read_u64(&mut rest)?,
                },
                // ── Fork LP Vault (tags 74-80) ───────────────────────────────
                74 => Self::CreateLpVault {
                    fee_share_bps: read_u16(&mut rest)?,
                    redemption_cooldown_slots: read_u64(&mut rest)?,
                    oi_reservation_threshold_bps: read_u16(&mut rest)?,
                    domain: read_u16(&mut rest)?,
                },
                75 => Self::DepositToLpVault {
                    amount: read_u128(&mut rest)?,
                    domain: read_u16(&mut rest)?,
                },
                91 => Self::RebalanceLpVaultBacking {
                    from_domain: read_u16(&mut rest)?,
                    to_domain: read_u16(&mut rest)?,
                    amount: read_u128(&mut rest)?,
                },
                76 => Self::RequestRedeemLpShares {
                    shares: read_u128(&mut rest)?,
                },
                77 => Self::ExecuteRedemption {
                    domain: read_u16(&mut rest)?,
                },
                78 => Self::LpVaultCrankFees {
                    domain: read_u16(&mut rest)?,
                },
                79 => Self::SetLpVaultPaused {
                    paused: read_u8(&mut rest)?,
                },
                80 => Self::CloseLpVault,
                81 => Self::CancelRedemption,
                // ── Fork NFT / B-3 (tags 72/73) ──────────────────────────────
                72 => Self::TransferPortfolioOwnership {
                    new_owner: read_bytes32(&mut rest)?,
                    asset_index: read_u16(&mut rest)?,
                },
                73 => Self::SetNftProgramId {
                    nft_program_id: read_bytes32(&mut rest)?,
                },
                82 => Self::UnwrapEscrowedPortfolio {
                    new_owner: read_bytes32(&mut rest)?,
                },
                83 => {
                    // InitMatcherCtx: bootstrap matcher context via CPI
                    let kind = read_u8(&mut rest)?;
                    let trading_fee_bps = read_u32(&mut rest)?;
                    let base_spread_bps = read_u32(&mut rest)?;
                    let max_total_bps = read_u32(&mut rest)?;
                    let impact_k_bps = read_u32(&mut rest)?;
                    let liquidity_notional_e6 = read_u128(&mut rest)?;
                    let max_fill_abs = read_u128(&mut rest)?;
                    let max_inventory_abs = read_u128(&mut rest)?;
                    let fee_to_insurance_bps = read_u16(&mut rest)?;
                    let skew_spread_mult_bps = read_u16(&mut rest)?;
                    Self::InitMatcherCtx {
                        kind,
                        trading_fee_bps,
                        base_spread_bps,
                        max_total_bps,
                        impact_k_bps,
                        liquidity_notional_e6,
                        max_fill_abs,
                        max_inventory_abs,
                        fee_to_insurance_bps,
                        skew_spread_mult_bps,
                    }
                }
                84 => Self::WithdrawProtocolFee {
                    amount: read_u128(&mut rest)?,
                },
                85 => Self::SetProtocolFeeAuthority {
                    new_authority: read_bytes32(&mut rest)?,
                },
                86 => Self::UpdateFeeSplit {
                    creator_share_bps: read_u16(&mut rest)?,
                    lp_share_bps: read_u16(&mut rest)?,
                    insurance_share_bps: read_u16(&mut rest)?,
                },
                87 => Self::WithdrawInsuranceReserveToStake,
                88 => Self::UpdateMaintenanceFeePerSlot {
                    maintenance_fee_per_slot: read_u128(&mut rest)?,
                },
                89 => Self::ExpireBackingBucket {
                    domain: read_u16(&mut rest)?,
                },
                90 => Self::WithdrawCreatorFee {
                    amount: read_u128(&mut rest)?,
                },
                _ => return Err(ProgramError::InvalidInstructionData),
            };
            if !rest.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok(ix)
        }

        pub fn encode(&self) -> Vec<u8> {
            let mut out = Vec::new();
            match *self {
                Self::InitMarket {
                    max_portfolio_assets,
                    h_min,
                    h_max,
                    initial_price,
                    min_nonzero_mm_req,
                    min_nonzero_im_req,
                    maintenance_margin_bps,
                    initial_margin_bps,
                    max_trading_fee_bps,
                    trade_fee_base_bps,
                    liquidation_fee_bps,
                    liquidation_fee_cap,
                    min_liquidation_abs,
                    max_price_move_bps_per_slot,
                    max_accrual_dt_slots,
                    max_abs_funding_e9_per_slot,
                    min_funding_lifetime_slots,
                    max_account_b_settlement_chunks,
                    max_bankrupt_close_chunks,
                    max_bankrupt_close_lifetime_slots,
                    public_b_chunk_atoms,
                    maintenance_fee_per_slot,
                } => {
                    out.push(0);
                    push_u16(&mut out, max_portfolio_assets);
                    push_u64(&mut out, h_min);
                    push_u64(&mut out, h_max);
                    push_u64(&mut out, initial_price);
                    push_u128(&mut out, min_nonzero_mm_req);
                    push_u128(&mut out, min_nonzero_im_req);
                    push_u64(&mut out, maintenance_margin_bps);
                    push_u64(&mut out, initial_margin_bps);
                    push_u64(&mut out, max_trading_fee_bps);
                    push_u64(&mut out, trade_fee_base_bps);
                    push_u64(&mut out, liquidation_fee_bps);
                    push_u128(&mut out, liquidation_fee_cap);
                    push_u128(&mut out, min_liquidation_abs);
                    push_u64(&mut out, max_price_move_bps_per_slot);
                    push_u64(&mut out, max_accrual_dt_slots);
                    push_u64(&mut out, max_abs_funding_e9_per_slot);
                    push_u64(&mut out, min_funding_lifetime_slots);
                    push_u64(&mut out, max_account_b_settlement_chunks);
                    push_u64(&mut out, max_bankrupt_close_chunks);
                    push_u64(&mut out, max_bankrupt_close_lifetime_slots);
                    push_u128(&mut out, public_b_chunk_atoms);
                    push_u128(&mut out, maintenance_fee_per_slot);
                }
                Self::InitPortfolio => out.push(1),
                Self::Deposit { amount } => {
                    out.push(3);
                    push_u128(&mut out, amount);
                }
                Self::Withdraw { amount } => {
                    out.push(4);
                    push_u128(&mut out, amount);
                }
                Self::PermissionlessCrank {
                    action,
                    asset_index,
                    now_slot,
                    funding_rate_e9,
                    recovery_reason,
                } => {
                    out.push(5);
                    out.push(action);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_i128(&mut out, funding_rate_e9);
                    out.push(recovery_reason);
                }
                Self::TradeNoCpi {
                    asset_index,
                    size_q,
                    exec_price,
                    fee_bps,
                } => {
                    out.push(6);
                    push_u16(&mut out, asset_index);
                    push_i128(&mut out, size_q);
                    push_u64(&mut out, exec_price);
                    push_u64(&mut out, fee_bps);
                }
                Self::TradeCpi {
                    asset_index,
                    size_q,
                    fee_bps,
                    limit_price,
                } => {
                    out.push(10);
                    push_u16(&mut out, asset_index);
                    push_i128(&mut out, size_q);
                    push_u64(&mut out, fee_bps);
                    push_u64(&mut out, limit_price);
                }
                Self::BatchTradeNoCpi { ref legs } => {
                    out.push(66);
                    out.push(legs.len() as u8);
                    for leg in legs.iter() {
                        push_u16(&mut out, leg.asset_index);
                        push_i128(&mut out, leg.size_q);
                        push_u64(&mut out, leg.exec_price);
                        push_u64(&mut out, leg.fee_bps);
                    }
                }
                Self::BatchTradeCpi { ref legs } => {
                    out.push(67);
                    out.push(legs.len() as u8);
                    for leg in legs.iter() {
                        push_u16(&mut out, leg.asset_index);
                        push_i128(&mut out, leg.size_q);
                        push_u64(&mut out, leg.fee_bps);
                        push_u64(&mut out, leg.limit_price);
                    }
                }
                Self::SetMatcherConfig { enabled } => {
                    out.push(68);
                    out.push(enabled);
                }
                Self::ClosePortfolio => out.push(8),
                Self::TopUpInsurance { amount } => {
                    out.push(9);
                    push_u128(&mut out, amount);
                }
                Self::TopUpInsuranceDomain { domain, amount } => {
                    out.push(56);
                    push_u16(&mut out, domain);
                    push_u128(&mut out, amount);
                }
                Self::CloseSlab => out.push(13),
                Self::ResolveMarket => out.push(19),
                Self::RebalanceLpVaultBacking {
                    from_domain,
                    to_domain,
                    amount,
                } => {
                    out.push(91);
                    push_u16(&mut out, from_domain);
                    push_u16(&mut out, to_domain);
                    push_u128(&mut out, amount);
                }
                Self::TopUpBackingBucket {
                    domain,
                    amount,
                    expiry_slot,
                } => {
                    out.push(24);
                    push_u16(&mut out, domain);
                    push_u128(&mut out, amount);
                    push_u64(&mut out, expiry_slot);
                }
                Self::WithdrawBackingBucket { domain, amount } => {
                    out.push(50);
                    push_u16(&mut out, domain);
                    push_u128(&mut out, amount);
                }
                Self::ConvertReleasedPnl { amount } => {
                    out.push(28);
                    push_u128(&mut out, amount);
                }
                Self::CloseResolved { fee_rate_per_slot } => {
                    out.push(30);
                    push_u128(&mut out, fee_rate_per_slot);
                }
                Self::UpdateAuthority { new_pubkey } => {
                    out.push(32);
                    out.extend_from_slice(&new_pubkey);
                }
                Self::UpdateAssetAuthority {
                    asset_index,
                    kind,
                    new_pubkey,
                } => {
                    out.push(65);
                    push_u16(&mut out, asset_index);
                    out.push(kind);
                    out.extend_from_slice(&new_pubkey);
                }
                Self::UpdateLiquidationFeePolicy { cranker_share_bps } => {
                    out.push(37);
                    push_u16(&mut out, cranker_share_bps);
                }
                Self::UpdateMaintenanceFeePolicy { cranker_share_bps } => {
                    out.push(49);
                    push_u16(&mut out, cranker_share_bps);
                }
                Self::UpdateBackingFeePolicy {
                    domain,
                    fee_bps,
                    insurance_share_bps,
                } => {
                    out.push(51);
                    push_u16(&mut out, domain);
                    push_u16(&mut out, fee_bps);
                    push_u16(&mut out, insurance_share_bps);
                }
                Self::UpdateTradeFeePolicy { trade_fee_base_bps } => {
                    out.push(55);
                    push_u64(&mut out, trade_fee_base_bps);
                }
                Self::UpdateFeeRedirectPolicy { redirect_bps } => {
                    out.push(58);
                    push_u16(&mut out, redirect_bps);
                }
                Self::UpdateInsuranceWithdrawPolicy {
                    deposits_only,
                    cooldown_slots,
                } => {
                    out.push(92);
                    out.push(deposits_only);
                    push_u64(&mut out, cooldown_slots);
                }
                Self::UpdateMarketInitFeePolicy { min_init_fee } => {
                    out.push(59);
                    push_u128(&mut out, min_init_fee);
                }
                Self::UpdateBaseUnitMints {
                    primary_mint,
                    secondary_mint,
                } => {
                    out.push(60);
                    out.extend_from_slice(&primary_mint);
                    out.extend_from_slice(&secondary_mint);
                }
                Self::SwapSecondaryForPrimary { amount } => {
                    out.push(61);
                    push_u128(&mut out, amount);
                }
                Self::WithdrawBackingBucketEarnings { domain, amount } => {
                    out.push(52);
                    push_u16(&mut out, domain);
                    push_u128(&mut out, amount);
                }
                Self::SyncBackingDomainLedger { domain } => {
                    out.push(53);
                    push_u16(&mut out, domain);
                }
                Self::SyncInsuranceLedger => out.push(54),
                Self::ConfigurePermissionlessResolve {
                    stale_slots,
                    force_close_delay_slots,
                } => {
                    out.push(38);
                    push_u64(&mut out, stale_slots);
                    push_u64(&mut out, force_close_delay_slots);
                }
                Self::ResolveStalePermissionless { now_slot } => {
                    out.push(39);
                    push_u64(&mut out, now_slot);
                }
                Self::ConfigureHybridOracle {
                    asset_index,
                    now_slot,
                    now_unix_ts,
                    oracle_leg_count,
                    oracle_leg_flags,
                    max_staleness_secs,
                    hybrid_soft_stale_slots,
                    mark_ewma_halflife_slots,
                    mark_min_fee,
                    invert,
                    unit_scale,
                    conf_filter_bps,
                    oracle_leg_feeds,
                } => {
                    out.push(34);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_i64(&mut out, now_unix_ts);
                    out.push(oracle_leg_count);
                    out.push(oracle_leg_flags);
                    push_u64(&mut out, max_staleness_secs);
                    push_u64(&mut out, hybrid_soft_stale_slots);
                    push_u64(&mut out, mark_ewma_halflife_slots);
                    push_u64(&mut out, mark_min_fee);
                    out.push(invert);
                    push_u32(&mut out, unit_scale);
                    push_u16(&mut out, conf_filter_bps);
                    for feed in oracle_leg_feeds {
                        out.extend_from_slice(&feed);
                    }
                }
                Self::ConfigureEwmaMark {
                    asset_index,
                    now_slot,
                    initial_mark_e6,
                    mark_ewma_halflife_slots,
                    mark_min_fee,
                } => {
                    out.push(35);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, initial_mark_e6);
                    push_u64(&mut out, mark_ewma_halflife_slots);
                    push_u64(&mut out, mark_min_fee);
                }
                Self::PushEwmaMark {
                    asset_index,
                    now_slot,
                    mark_e6,
                } => {
                    out.push(36);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, mark_e6);
                }
                Self::ConfigureAuthMark {
                    asset_index,
                    now_slot,
                    initial_mark_e6,
                } => {
                    out.push(62);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, initial_mark_e6);
                }
                Self::PushAuthMark {
                    asset_index,
                    now_slot,
                    mark_e6,
                } => {
                    out.push(63);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, mark_e6);
                }
                Self::ForceCloseAbandonedAsset {
                    asset_index,
                    now_slot,
                    close_q,
                } => {
                    out.push(64);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u128(&mut out, close_q);
                }
                Self::RestartAssetOracle {
                    asset_index,
                    now_slot,
                    initial_price,
                } => {
                    out.push(69);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, initial_price);
                }
                Self::UpdateAssetLifecycle {
                    action,
                    asset_index,
                    now_slot,
                    initial_price,
                    insurance_authority,
                    insurance_operator,
                    backing_bucket_authority,
                    oracle_authority,
                } => {
                    out.push(40);
                    out.push(action);
                    push_u16(&mut out, asset_index);
                    push_u64(&mut out, now_slot);
                    push_u64(&mut out, initial_price);
                    out.extend_from_slice(&insurance_authority);
                    out.extend_from_slice(&insurance_operator);
                    out.extend_from_slice(&backing_bucket_authority);
                    out.extend_from_slice(&oracle_authority);
                }
                Self::WithdrawInsurance { amount } => {
                    out.push(41);
                    push_u128(&mut out, amount);
                }
                Self::WithdrawInsuranceAsset {
                    asset_index,
                    amount,
                } => {
                    out.push(57);
                    push_u16(&mut out, asset_index);
                    push_u128(&mut out, amount);
                }
                Self::CureAndCancelClose { optional_deposit } => {
                    out.push(42);
                    push_u128(&mut out, optional_deposit);
                }
                Self::ForfeitRecoveryLeg {
                    asset_index,
                    b_delta_budget,
                } => {
                    out.push(43);
                    push_u16(&mut out, asset_index);
                    push_u128(&mut out, b_delta_budget);
                }
                Self::RebalanceReduce {
                    asset_index,
                    reduce_q,
                } => {
                    out.push(44);
                    push_u16(&mut out, asset_index);
                    push_u128(&mut out, reduce_q);
                }
                Self::FinalizeResetSide { asset_index, side } => {
                    out.push(45);
                    push_u16(&mut out, asset_index);
                    out.push(side);
                }
                Self::ClaimResolvedPayoutTopup => out.push(46),
                Self::RefineResolvedUnreceiptedBound { decrease_num } => {
                    out.push(47);
                    push_u128(&mut out, decrease_num);
                }
                Self::SyncMaintenanceFee { now_slot } => {
                    out.push(48);
                    push_u64(&mut out, now_slot);
                }
                // ── Fork LP Vault (tags 74-80) ───────────────────────────────
                Self::CreateLpVault {
                    fee_share_bps,
                    redemption_cooldown_slots,
                    oi_reservation_threshold_bps,
                    domain,
                } => {
                    out.push(74);
                    push_u16(&mut out, fee_share_bps);
                    push_u64(&mut out, redemption_cooldown_slots);
                    push_u16(&mut out, oi_reservation_threshold_bps);
                    push_u16(&mut out, domain);
                }
                Self::DepositToLpVault { amount, domain } => {
                    out.push(75);
                    push_u128(&mut out, amount);
                    push_u16(&mut out, domain);
                }
                Self::RequestRedeemLpShares { shares } => {
                    out.push(76);
                    push_u128(&mut out, shares);
                }
                Self::ExecuteRedemption { domain } => {
                    out.push(77);
                    push_u16(&mut out, domain);
                }
                Self::LpVaultCrankFees { domain } => {
                    out.push(78);
                    push_u16(&mut out, domain);
                }
                Self::SetLpVaultPaused { paused } => {
                    out.push(79);
                    out.push(paused);
                }
                Self::CloseLpVault => out.push(80),
                Self::CancelRedemption => out.push(81),
                // ── Fork NFT / B-3 (tags 72/73) ──────────────────────────────
                Self::TransferPortfolioOwnership {
                    new_owner,
                    asset_index,
                } => {
                    out.push(72);
                    out.extend_from_slice(&new_owner);
                    push_u16(&mut out, asset_index);
                }
                Self::SetNftProgramId { nft_program_id } => {
                    out.push(73);
                    out.extend_from_slice(&nft_program_id);
                }
                Self::UnwrapEscrowedPortfolio { new_owner } => {
                    out.push(82);
                    out.extend_from_slice(&new_owner);
                }
                Self::InitMatcherCtx {
                    kind,
                    trading_fee_bps,
                    base_spread_bps,
                    max_total_bps,
                    impact_k_bps,
                    liquidity_notional_e6,
                    max_fill_abs,
                    max_inventory_abs,
                    fee_to_insurance_bps,
                    skew_spread_mult_bps,
                } => {
                    out.push(83);
                    out.push(kind);
                    out.extend_from_slice(&trading_fee_bps.to_le_bytes());
                    out.extend_from_slice(&base_spread_bps.to_le_bytes());
                    out.extend_from_slice(&max_total_bps.to_le_bytes());
                    out.extend_from_slice(&impact_k_bps.to_le_bytes());
                    out.extend_from_slice(&liquidity_notional_e6.to_le_bytes());
                    out.extend_from_slice(&max_fill_abs.to_le_bytes());
                    out.extend_from_slice(&max_inventory_abs.to_le_bytes());
                    out.extend_from_slice(&fee_to_insurance_bps.to_le_bytes());
                    out.extend_from_slice(&skew_spread_mult_bps.to_le_bytes());
                }
                Self::WithdrawProtocolFee { amount } => {
                    out.push(84);
                    push_u128(&mut out, amount);
                }
                Self::SetProtocolFeeAuthority { new_authority } => {
                    out.push(85);
                    out.extend_from_slice(&new_authority);
                }
                Self::UpdateFeeSplit {
                    creator_share_bps,
                    lp_share_bps,
                    insurance_share_bps,
                } => {
                    out.push(86);
                    push_u16(&mut out, creator_share_bps);
                    push_u16(&mut out, lp_share_bps);
                    push_u16(&mut out, insurance_share_bps);
                }
                Self::WithdrawInsuranceReserveToStake => out.push(87),
                Self::UpdateMaintenanceFeePerSlot {
                    maintenance_fee_per_slot,
                } => {
                    out.push(88);
                    push_u128(&mut out, maintenance_fee_per_slot);
                }
                Self::ExpireBackingBucket { domain } => {
                    out.push(89);
                    push_u16(&mut out, domain);
                }
                Self::WithdrawCreatorFee { amount } => {
                    out.push(90);
                    push_u128(&mut out, amount);
                }
            }
            out
        }
    }

    fn read_u8(input: &mut &[u8]) -> Result<u8, ProgramError> {
        let (&v, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        *input = rest;
        Ok(v)
    }

    fn read_u64(input: &mut &[u8]) -> Result<u64, ProgramError> {
        if input.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(8);
        *input = rest;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u16(input: &mut &[u8]) -> Result<u16, ProgramError> {
        if input.len() < 2 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(2);
        *input = rest;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u32(input: &mut &[u8]) -> Result<u32, ProgramError> {
        if input.len() < 4 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(4);
        *input = rest;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u128(input: &mut &[u8]) -> Result<u128, ProgramError> {
        if input.len() < 16 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(16);
        *input = rest;
        Ok(u128::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_i128(input: &mut &[u8]) -> Result<i128, ProgramError> {
        if input.len() < 16 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(16);
        *input = rest;
        Ok(i128::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_i64(input: &mut &[u8]) -> Result<i64, ProgramError> {
        if input.len() < 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(8);
        *input = rest;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_bytes32(input: &mut &[u8]) -> Result<[u8; 32], ProgramError> {
        if input.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (bytes, rest) = input.split_at(32);
        *input = rest;
        Ok(bytes.try_into().unwrap())
    }

    fn push_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u128(out: &mut Vec<u8>, v: u128) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_i128(out: &mut Vec<u8>, v: i128) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_i64(out: &mut Vec<u8>, v: i64) {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

pub mod matcher_abi {
    use crate::constants::MATCHER_ABI_VERSION;
    use solana_program::program_error::ProgramError;

    /// Wire size of one serialized MatcherReturn.
    pub const MATCHER_RETURN_BYTES: usize = 64;

    pub const FLAG_VALID: u32 = 1;
    pub const FLAG_PARTIAL_OK: u32 = 2;
    pub const FLAG_REJECTED: u32 = 4;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MatcherReturn {
        pub abi_version: u32,
        pub flags: u32,
        pub exec_price_e6: u64,
        pub exec_size: i128,
        pub req_id: u64,
        pub lp_account_id: u64,
        pub oracle_price_e6: u64,
        pub asset_index: u64,
    }

    pub fn read_matcher_return(ctx: &[u8]) -> Result<MatcherReturn, ProgramError> {
        if ctx.len() < 64 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(MatcherReturn {
            abi_version: u32::from_le_bytes(ctx[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(ctx[4..8].try_into().unwrap()),
            exec_price_e6: u64::from_le_bytes(ctx[8..16].try_into().unwrap()),
            exec_size: i128::from_le_bytes(ctx[16..32].try_into().unwrap()),
            req_id: u64::from_le_bytes(ctx[32..40].try_into().unwrap()),
            lp_account_id: u64::from_le_bytes(ctx[40..48].try_into().unwrap()),
            oracle_price_e6: u64::from_le_bytes(ctx[48..56].try_into().unwrap()),
            asset_index: u64::from_le_bytes(ctx[56..64].try_into().unwrap()),
        })
    }

    pub fn validate_matcher_return(
        ret: &MatcherReturn,
        lp_account_id: u64,
        asset_index: u16,
        oracle_price_e6: u64,
        req_size: i128,
        req_id: u64,
    ) -> Result<(), ProgramError> {
        if ret.abi_version != MATCHER_ABI_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        const KNOWN_FLAGS: u32 = FLAG_VALID | FLAG_PARTIAL_OK | FLAG_REJECTED;
        if (ret.flags & !KNOWN_FLAGS) != 0
            || (ret.flags & FLAG_VALID) == 0
            || (ret.flags & FLAG_REJECTED) != 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.lp_account_id != lp_account_id
            || ret.oracle_price_e6 != oracle_price_e6
            || ret.asset_index != asset_index as u64
            || ret.req_id != req_id
            || ret.exec_price_e6 == 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.exec_size == 0 {
            if (ret.flags & FLAG_PARTIAL_OK) == 0 || ret.exec_price_e6 != oracle_price_e6 {
                return Err(ProgramError::InvalidAccountData);
            }
            return Ok(());
        }
        if ret.exec_size == i128::MIN || req_size == i128::MIN || req_size == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.exec_size.signum() != req_size.signum() {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.exec_size.unsigned_abs() > req_size.unsigned_abs() {
            return Err(ProgramError::InvalidAccountData);
        }
        if ret.exec_size.unsigned_abs() < req_size.unsigned_abs()
            && (ret.flags & FLAG_PARTIAL_OK) == 0
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }
}

pub mod oracle_v16 {
    use crate::{
        constants::{
            ORACLE_LEG_CAP, ORACLE_LEG_FLAGS_MASK, ORACLE_LEG_FLAG_DIVIDE_LEG2,
            ORACLE_LEG_FLAG_DIVIDE_LEG3, ORACLE_MODE_AUTH_MARK, ORACLE_MODE_EWMA_MARK,
            ORACLE_MODE_HYBRID_AFTER_HOURS, ORACLE_MODE_MANUAL, SWITCHBOARD_RESULT_SCALE,
        },
        error::PercolatorError,
        state::{AssetOracleProfileV16, WrapperConfigV16},
    };
    use borsh::BorshDeserialize;
    use pythnet_sdk::messages::PriceFeedMessage;
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

    pub const PYTH_RECEIVER_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
        0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48, 0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b,
        0x90, 0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01, 0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38,
        0x58, 0x81,
    ]);
    pub const SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID: Pubkey =
        solana_program::pubkey!("SBondMDrcV3K4kxZR1HNVT7osZxAHVHgYXL5Ze1oMUv");
    pub const SWITCHBOARD_ON_DEMAND_DEVNET_PROGRAM_ID: Pubkey =
        solana_program::pubkey!("Aio4gaXjXzJNVLtzwtNVmSqGKpANtXhybbkhtAC94ji2");
    pub const CHAINLINK_STORE_PROGRAM_ID: Pubkey =
        solana_program::pubkey!("HEvSKofvBgfaexv23kMabbYqxasxU3mQ4ibBMEmJWHny");
    const PRICE_UPDATE_V2_MIN_LEN: usize = 134;
    const OFF_VERIFICATION_LEVEL: usize = 40;
    const OFF_PRICE_FEED_MESSAGE: usize = 41;
    const PYTH_PRICE_UPDATE_V2_DISCRIMINATOR: [u8; 8] =
        [0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd];
    const PYTH_VERIFICATION_FULL_TAG: u8 = 1;
    const MAX_EXPO_ABS: i32 = 18;
    const SWITCHBOARD_PULL_FEED_DISCRIMINATOR: [u8; 8] = [196, 27, 108, 196, 10, 215, 219, 40];
    const SWITCHBOARD_PULL_FEED_MIN_LEN: usize = 3_208;
    const SB_OFF_FEED_HASH: usize = 8 + 2_112;
    const SB_OFF_MIN_SAMPLE_SIZE: usize = 8 + 2_207;
    const SB_OFF_LAST_UPDATE_TIMESTAMP: usize = 8 + 2_208;
    const SB_OFF_RESULT_VALUE: usize = 8 + 2_256;
    const SB_OFF_RESULT_STD_DEV: usize = 8 + 2_272;
    const SB_OFF_RESULT_NUM_SAMPLES: usize = 8 + 2_352;
    const SB_OFF_RESULT_SLOT: usize = 8 + 2_360;
    const CHAINLINK_TRANSMISSIONS_DISCRIMINATOR: [u8; 8] = [96, 179, 69, 66, 128, 129, 73, 117];
    const CHAINLINK_HEADER_SIZE: usize = 192;
    const CHAINLINK_FEED_MIN_LEN: usize = 8 + CHAINLINK_HEADER_SIZE + 48;
    const CL_OFF_VERSION: usize = 8;
    const CL_OFF_DECIMALS: usize = 138;
    const CL_OFF_LATEST_ROUND_ID: usize = 143;
    const CL_OFF_LIVE_LENGTH: usize = 148;
    const CL_OFF_TRANSMISSION: usize = 8 + CHAINLINK_HEADER_SIZE;
    const CL_TRANS_OFF_SLOT: usize = 0;
    const CL_TRANS_OFF_TIMESTAMP: usize = 8;
    const CL_TRANS_OFF_ANSWER: usize = 16;

    pub fn is_hybrid(config: &WrapperConfigV16) -> bool {
        config.oracle_mode == ORACLE_MODE_HYBRID_AFTER_HOURS
    }

    pub fn is_ewma_mark(config: &WrapperConfigV16) -> bool {
        config.oracle_mode == ORACLE_MODE_EWMA_MARK
    }

    pub fn is_auth_mark(config: &WrapperConfigV16) -> bool {
        config.oracle_mode == ORACLE_MODE_AUTH_MARK
    }

    pub fn profile_is_hybrid(profile: &AssetOracleProfileV16) -> bool {
        profile.oracle_mode == ORACLE_MODE_HYBRID_AFTER_HOURS
    }

    pub fn profile_is_ewma_mark(profile: &AssetOracleProfileV16) -> bool {
        profile.oracle_mode == ORACLE_MODE_EWMA_MARK
    }

    pub fn profile_is_auth_mark(profile: &AssetOracleProfileV16) -> bool {
        profile.oracle_mode == ORACLE_MODE_AUTH_MARK
    }

    pub fn profile_is_price_managed(profile: &AssetOracleProfileV16) -> bool {
        profile_is_hybrid(profile) || profile_is_ewma_mark(profile) || profile_is_auth_mark(profile)
    }

    pub fn hybrid_soft_stale_matured(config: &WrapperConfigV16, now_slot: u64) -> bool {
        is_hybrid(config)
            && config.hybrid_soft_stale_slots != 0
            && now_slot.saturating_sub(config.last_good_oracle_slot)
                > config.hybrid_soft_stale_slots
    }

    pub fn profile_hybrid_soft_stale_matured(
        profile: &AssetOracleProfileV16,
        now_slot: u64,
    ) -> bool {
        profile_is_hybrid(profile)
            && profile.hybrid_soft_stale_slots != 0
            && now_slot.saturating_sub(profile.last_good_oracle_slot)
                > profile.hybrid_soft_stale_slots
    }

    pub fn hard_stale_matured(config: &WrapperConfigV16, now_slot: u64) -> bool {
        is_hybrid(config) && permissionless_stale_matured(config, now_slot)
    }

    pub fn permissionless_stale_matured(config: &WrapperConfigV16, now_slot: u64) -> bool {
        config.permissionless_resolve_stale_slots != 0
            && now_slot.saturating_sub(config.last_good_oracle_slot)
                >= config.permissionless_resolve_stale_slots
    }

    pub fn oracle_leg_config_ok(count: u8, flags: u8, feeds: &[[u8; 32]; ORACLE_LEG_CAP]) -> bool {
        if flags & !ORACLE_LEG_FLAGS_MASK != 0 {
            return false;
        }
        if count == 0 {
            return flags == 0 && feeds.iter().all(|f| *f == [0u8; 32]);
        }
        if count > ORACLE_LEG_CAP as u8 || feeds[0] == [0u8; 32] {
            return false;
        }
        if count == 1 {
            return flags == 0 && feeds[1] == [0u8; 32] && feeds[2] == [0u8; 32];
        }
        if feeds[1] == [0u8; 32] || feeds[1] == feeds[0] {
            return false;
        }
        if count == 2 {
            return (flags & ORACLE_LEG_FLAG_DIVIDE_LEG3) == 0 && feeds[2] == [0u8; 32];
        }
        feeds[2] != [0u8; 32] && feeds[2] != feeds[0] && feeds[2] != feeds[1]
    }

    fn leg_divides(config: &WrapperConfigV16, idx: usize) -> bool {
        match idx {
            1 => (config.oracle_leg_flags & ORACLE_LEG_FLAG_DIVIDE_LEG2) != 0,
            2 => (config.oracle_leg_flags & ORACLE_LEG_FLAG_DIVIDE_LEG3) != 0,
            _ => false,
        }
    }

    fn profile_leg_divides(profile: &AssetOracleProfileV16, idx: usize) -> bool {
        match idx {
            1 => (profile.oracle_leg_flags & ORACLE_LEG_FLAG_DIVIDE_LEG2) != 0,
            2 => (profile.oracle_leg_flags & ORACLE_LEG_FLAG_DIVIDE_LEG3) != 0,
            _ => false,
        }
    }

    pub fn read_pyth_price_e6(
        price_ai: &AccountInfo,
        expected_feed_id: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
        conf_bps: u16,
    ) -> Result<(u64, i64), ProgramError> {
        if *price_ai.owner != PYTH_RECEIVER_PROGRAM_ID {
            return Err(ProgramError::IllegalOwner);
        }
        let data = price_ai.try_borrow_data()?;
        if data.len() < PRICE_UPDATE_V2_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[..8] != PYTH_PRICE_UPDATE_V2_DISCRIMINATOR {
            return Err(PercolatorError::OracleInvalid.into());
        }
        if data[OFF_VERIFICATION_LEVEL] != PYTH_VERIFICATION_FULL_TAG {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let msg = <PriceFeedMessage as BorshDeserialize>::deserialize(
            &mut &data[OFF_PRICE_FEED_MESSAGE..],
        )
        .map_err(|_| PercolatorError::OracleInvalid)?;
        if &msg.feed_id != expected_feed_id {
            return Err(PercolatorError::InvalidOracleKey.into());
        }
        if msg.price <= 0 || msg.exponent < -MAX_EXPO_ABS || msg.exponent > MAX_EXPO_ABS {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let age = now_unix_ts.saturating_sub(msg.publish_time);
        if age < 0 || age as u64 > max_staleness_secs {
            return Err(PercolatorError::OracleStale.into());
        }
        let price_u = msg.price as u128;
        if conf_bps != 0 && (msg.conf as u128).saturating_mul(10_000) > price_u * conf_bps as u128 {
            return Err(PercolatorError::OracleConfTooWide.into());
        }
        let scale = msg.exponent + 6;
        let out = if scale >= 0 {
            price_u
                .checked_mul(10u128.pow(scale as u32))
                .ok_or(PercolatorError::EngineArithmeticOverflow)?
        } else {
            price_u / 10u128.pow((-scale) as u32)
        };
        if out == 0 || out > percolator::MAX_ORACLE_PRICE as u128 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        Ok((out as u64, msg.publish_time))
    }

    #[inline]
    fn read_u32_le(data: &[u8], off: usize) -> Result<u32, ProgramError> {
        let bytes: [u8; 4] = data
            .get(off..off + 4)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .unwrap();
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    fn read_u64_le(data: &[u8], off: usize) -> Result<u64, ProgramError> {
        let bytes: [u8; 8] = data
            .get(off..off + 8)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .unwrap();
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    fn read_i64_le(data: &[u8], off: usize) -> Result<i64, ProgramError> {
        let bytes: [u8; 8] = data
            .get(off..off + 8)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .unwrap();
        Ok(i64::from_le_bytes(bytes))
    }

    #[inline]
    fn read_i128_le(data: &[u8], off: usize) -> Result<i128, ProgramError> {
        let bytes: [u8; 16] = data
            .get(off..off + 16)
            .ok_or(ProgramError::InvalidAccountData)?
            .try_into()
            .unwrap();
        Ok(i128::from_le_bytes(bytes))
    }

    fn scale_decimal_to_e6(mantissa: i128, scale: u32) -> Result<u64, ProgramError> {
        if mantissa <= 0 || scale > MAX_EXPO_ABS as u32 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let mantissa = mantissa as u128;
        let out = if scale >= 6 {
            mantissa / 10u128.pow(scale - 6)
        } else {
            mantissa
                .checked_mul(10u128.pow(6 - scale))
                .ok_or(PercolatorError::EngineArithmeticOverflow)?
        };
        if out == 0 || out > percolator::MAX_ORACLE_PRICE as u128 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        Ok(out as u64)
    }

    pub fn read_switchboard_price_e6(
        price_ai: &AccountInfo,
        expected_feed_key: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
        conf_bps: u16,
    ) -> Result<(u64, i64), ProgramError> {
        if *price_ai.owner != SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID
            && *price_ai.owner != SWITCHBOARD_ON_DEMAND_DEVNET_PROGRAM_ID
        {
            return Err(ProgramError::IllegalOwner);
        }
        if price_ai.key.to_bytes() != *expected_feed_key {
            return Err(PercolatorError::InvalidOracleKey.into());
        }
        let data = price_ai.try_borrow_data()?;
        if data.len() < SWITCHBOARD_PULL_FEED_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[..8] != SWITCHBOARD_PULL_FEED_DISCRIMINATOR {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let feed_hash: [u8; 32] = data[SB_OFF_FEED_HASH..SB_OFF_FEED_HASH + 32]
            .try_into()
            .unwrap();
        let min_sample_size = data[SB_OFF_MIN_SAMPLE_SIZE];
        let publish_time = read_i64_le(&data, SB_OFF_LAST_UPDATE_TIMESTAMP)?;
        let value = read_i128_le(&data, SB_OFF_RESULT_VALUE)?;
        let std_dev = read_i128_le(&data, SB_OFF_RESULT_STD_DEV)?;
        let num_samples = data[SB_OFF_RESULT_NUM_SAMPLES];
        let result_slot = read_u64_le(&data, SB_OFF_RESULT_SLOT)?;
        if feed_hash == [0u8; 32]
            || min_sample_size == 0
            || num_samples < min_sample_size
            || result_slot == 0
            || publish_time <= 0
            || value <= 0
            || std_dev < 0
        {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let age = now_unix_ts.saturating_sub(publish_time);
        if age < 0 || age as u64 > max_staleness_secs {
            return Err(PercolatorError::OracleStale.into());
        }
        let value_u = value as u128;
        if conf_bps != 0 && (std_dev as u128).saturating_mul(10_000) > value_u * conf_bps as u128 {
            return Err(PercolatorError::OracleConfTooWide.into());
        }
        let out = value_u / SWITCHBOARD_RESULT_SCALE;
        if out == 0 || out > percolator::MAX_ORACLE_PRICE as u128 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        Ok((out as u64, publish_time))
    }

    pub fn read_chainlink_price_e6(
        price_ai: &AccountInfo,
        expected_feed_key: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
    ) -> Result<(u64, i64), ProgramError> {
        if *price_ai.owner != CHAINLINK_STORE_PROGRAM_ID {
            return Err(ProgramError::IllegalOwner);
        }
        if price_ai.key.to_bytes() != *expected_feed_key {
            return Err(PercolatorError::InvalidOracleKey.into());
        }
        let data = price_ai.try_borrow_data()?;
        if data.len() < CHAINLINK_FEED_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[..8] != CHAINLINK_TRANSMISSIONS_DISCRIMINATOR {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let version = data[CL_OFF_VERSION];
        let decimals = data[CL_OFF_DECIMALS];
        let latest_round_id = read_u32_le(&data, CL_OFF_LATEST_ROUND_ID)?;
        let live_length = read_u32_le(&data, CL_OFF_LIVE_LENGTH)?;
        let tx = CL_OFF_TRANSMISSION;
        let result_slot = read_u64_le(&data, tx + CL_TRANS_OFF_SLOT)?;
        let publish_time = read_u32_le(&data, tx + CL_TRANS_OFF_TIMESTAMP)? as i64;
        let answer = read_i128_le(&data, tx + CL_TRANS_OFF_ANSWER)?;
        if version == 0
            || latest_round_id == 0
            || live_length != 1
            || result_slot == 0
            || publish_time <= 0
        {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let age = now_unix_ts.saturating_sub(publish_time);
        if age < 0 || age as u64 > max_staleness_secs {
            return Err(PercolatorError::OracleStale.into());
        }
        scale_decimal_to_e6(answer, decimals as u32).map(|p| (p, publish_time))
    }

    pub fn read_oracle_price_e6(
        price_ai: &AccountInfo,
        expected_feed_id: &[u8; 32],
        now_unix_ts: i64,
        max_staleness_secs: u64,
        conf_bps: u16,
    ) -> Result<(u64, i64), ProgramError> {
        if *price_ai.owner == PYTH_RECEIVER_PROGRAM_ID {
            read_pyth_price_e6(
                price_ai,
                expected_feed_id,
                now_unix_ts,
                max_staleness_secs,
                conf_bps,
            )
        } else if *price_ai.owner == SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID
            || *price_ai.owner == SWITCHBOARD_ON_DEMAND_DEVNET_PROGRAM_ID
        {
            read_switchboard_price_e6(
                price_ai,
                expected_feed_id,
                now_unix_ts,
                max_staleness_secs,
                conf_bps,
            )
        } else if *price_ai.owner == CHAINLINK_STORE_PROGRAM_ID {
            read_chainlink_price_e6(price_ai, expected_feed_id, now_unix_ts, max_staleness_secs)
        } else {
            Err(ProgramError::IllegalOwner)
        }
    }

    fn apply_transform(raw_price: u64, invert: u8, unit_scale: u32) -> Result<u64, ProgramError> {
        let mut price = raw_price;
        // Guard zero BEFORE the invert divide: a multi-leg `compose` with a divide leg can floor the
        // accumulator to 0, and `1e12 / 0` would panic. A zero price is always OracleInvalid anyway
        // (the post-transform check below already rejects it), so this only converts the panic into
        // the same graceful error — no valid behavior changes (valid oracle prices are nonzero).
        if price == 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        if invert != 0 {
            price = (1_000_000_000_000u128 / price as u128)
                .try_into()
                .map_err(|_| PercolatorError::OracleInvalid)?;
        }
        if unit_scale > 1 {
            price /= unit_scale as u64;
        }
        if price == 0 || price > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::OracleInvalid.into());
        }
        Ok(price)
    }

    fn compose(acc_e6: u64, leg_e6: u64, divide: bool) -> Result<u64, ProgramError> {
        if leg_e6 == 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let next = if divide {
            (acc_e6 as u128)
                .checked_mul(1_000_000)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?
                / leg_e6 as u128
        } else {
            (acc_e6 as u128)
                .checked_mul(leg_e6 as u128)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?
                / 1_000_000
        };
        if next == 0 || next > percolator::MAX_ORACLE_PRICE as u128 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        Ok(next as u64)
    }

    pub fn read_external_price_e6(
        config: &mut WrapperConfigV16,
        oracle_accounts: &[AccountInfo],
        now_unix_ts: i64,
    ) -> Result<(u64, i64, bool), ProgramError> {
        if config.oracle_mode == ORACLE_MODE_MANUAL {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let count = config.oracle_leg_count as usize;
        if count == 0 || count > ORACLE_LEG_CAP || oracle_accounts.len() < count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        if !oracle_leg_config_ok(
            config.oracle_leg_count,
            config.oracle_leg_flags,
            &config.oracle_leg_feeds,
        ) {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let mut acc = 0u64;
        let mut advanced = false;
        let mut max_publish_time = i64::MIN;
        let mut i = 0usize;
        while i < count {
            let (price, publish_time) = read_oracle_price_e6(
                &oracle_accounts[i],
                &config.oracle_leg_feeds[i],
                now_unix_ts,
                config.max_staleness_secs,
                config.conf_filter_bps,
            )?;
            let prev_time = config.oracle_leg_publish_times[i];
            let prev_price = config.oracle_leg_prices_e6[i];
            if prev_time != 0 {
                if publish_time < prev_time {
                    return Err(PercolatorError::OracleStale.into());
                }
                if publish_time == prev_time && prev_price != 0 && price != prev_price {
                    return Err(PercolatorError::OracleInvalid.into());
                }
            }
            if publish_time > prev_time {
                config.oracle_leg_publish_times[i] = publish_time;
                config.oracle_leg_prices_e6[i] = price;
                advanced = true;
            }
            max_publish_time = core::cmp::max(max_publish_time, publish_time);
            acc = if i == 0 {
                price
            } else {
                compose(acc, price, leg_divides(config, i))?
            };
            i += 1;
        }
        Ok((
            apply_transform(acc, config.invert, config.unit_scale)?,
            max_publish_time,
            advanced,
        ))
    }

    pub fn read_external_price_e6_profile(
        profile: &mut AssetOracleProfileV16,
        oracle_accounts: &[AccountInfo],
        now_unix_ts: i64,
    ) -> Result<(u64, i64, bool), ProgramError> {
        if profile.oracle_mode == ORACLE_MODE_MANUAL {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let count = profile.oracle_leg_count as usize;
        if count == 0 || count > ORACLE_LEG_CAP || oracle_accounts.len() < count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        if !oracle_leg_config_ok(
            profile.oracle_leg_count,
            profile.oracle_leg_flags,
            &profile.oracle_leg_feeds,
        ) {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let mut acc = 0u64;
        let mut advanced = false;
        let mut max_publish_time = i64::MIN;
        let mut i = 0usize;
        while i < count {
            let (price, publish_time) = read_oracle_price_e6(
                &oracle_accounts[i],
                &profile.oracle_leg_feeds[i],
                now_unix_ts,
                profile.max_staleness_secs,
                profile.conf_filter_bps,
            )?;
            let prev_time = profile.oracle_leg_publish_times[i];
            let prev_price = profile.oracle_leg_prices_e6[i];
            if prev_time != 0 {
                if publish_time < prev_time {
                    return Err(PercolatorError::OracleStale.into());
                }
                if publish_time == prev_time && prev_price != 0 && price != prev_price {
                    return Err(PercolatorError::OracleInvalid.into());
                }
            }
            if publish_time > prev_time {
                profile.oracle_leg_publish_times[i] = publish_time;
                profile.oracle_leg_prices_e6[i] = price;
                advanced = true;
            }
            max_publish_time = core::cmp::max(max_publish_time, publish_time);
            acc = if i == 0 {
                price
            } else {
                compose(acc, price, profile_leg_divides(profile, i))?
            };
            i += 1;
        }
        Ok((
            apply_transform(acc, profile.invert, profile.unit_scale)?,
            max_publish_time,
            advanced,
        ))
    }

    pub fn clamp_toward_engine_dt(p_last: u64, target: u64, cap_bps: u64, dt_slots: u64) -> u64 {
        if p_last == 0 || target == 0 {
            return target;
        }
        if cap_bps == 0 || dt_slots == 0 {
            return p_last;
        }
        let max_delta = (p_last as u128)
            .saturating_mul(cap_bps as u128)
            .saturating_mul(dt_slots as u128)
            / 10_000;
        let max_delta = core::cmp::min(max_delta, u64::MAX as u128) as u64;
        if target > p_last {
            core::cmp::min(target, p_last.saturating_add(max_delta))
        } else {
            core::cmp::max(target, p_last.saturating_sub(max_delta))
        }
    }

    pub fn effective_price_from_target(
        anchor: u64,
        target: u64,
        max_change_bps: u64,
        dt_slots: u64,
        exposed: bool,
    ) -> u64 {
        if exposed {
            clamp_toward_engine_dt(anchor, target, max_change_bps, dt_slots)
        } else {
            target
        }
    }
}

pub mod policy_v16 {
    use crate::constants::{
        FEE_SHARE_TOTAL_BPS, MAX_CREATOR_SHARE_BPS, MAX_DYNAMIC_TRADE_FEE_BPS,
        MIN_INSURANCE_SHARE_BPS, MIN_LP_SHARE_BPS,
    };
    use crate::error::PercolatorError;
    use solana_program::program_error::ProgramError;

    pub fn price_move_bps_ceil(old: u64, new: u64) -> Option<u64> {
        if old == 0 || old == new {
            return Some(0);
        }
        let diff = old.abs_diff(new) as u128;
        let den = old as u128;
        let bps = diff.checked_mul(10_000)?.checked_add(den.checked_sub(1)?)? / den;
        u64::try_from(bps).ok()
    }

    pub fn premium_funding_rate_e9(
        mark_e6: u64,
        index_e6: u64,
        max_abs_rate_e9: u64,
    ) -> Option<i128> {
        if max_abs_rate_e9 == 0 || mark_e6 == 0 || index_e6 == 0 || mark_e6 == index_e6 {
            return Some(0);
        }
        let premium_e9 = (mark_e6.abs_diff(index_e6) as u128)
            .checked_mul(percolator::FUNDING_DEN)?
            / index_e6 as u128;
        let bounded = core::cmp::min(premium_e9, max_abs_rate_e9 as u128);
        let signed = i128::try_from(bounded).ok()?;
        if mark_e6 > index_e6 {
            Some(signed)
        } else {
            Some(-signed)
        }
    }

    fn two_sided_trade_fee_paid_cap(notional: u128, fee_bps: u64) -> Option<u64> {
        if notional == 0 || fee_bps == 0 {
            return Some(0);
        }
        let one_side = notional.checked_mul(fee_bps as u128)?.checked_add(9_999)? / 10_000;
        u64::try_from(one_side.checked_mul(2)?).ok()
    }

    fn ceil_div_u128(num: u128, den: u128) -> Option<u128> {
        if den == 0 {
            return None;
        }
        Some(num.checked_add(den.checked_sub(1)?)? / den)
    }

    fn ewma_effective_alpha_bps(alpha_bps: u128, fee_paid: u64, mark_min_fee: u64) -> u128 {
        if mark_min_fee == 0 || fee_paid >= mark_min_fee {
            alpha_bps
        } else {
            alpha_bps.saturating_mul(fee_paid as u128) / mark_min_fee as u128
        }
    }

    pub fn ewma_update(
        old: u64,
        price: u64,
        halflife_slots: u64,
        last_slot: u64,
        now_slot: u64,
        fee_paid: u64,
        mark_min_fee: u64,
    ) -> u64 {
        if old == 0 {
            if mark_min_fee > 0 && fee_paid < mark_min_fee {
                return 0;
            }
            return price;
        }
        let dt = now_slot.saturating_sub(last_slot);
        if dt == 0 {
            return old;
        }
        if halflife_slots == 0 {
            return price;
        }
        if fee_paid == 0 && mark_min_fee > 0 {
            return old;
        }
        let alpha_bps = (10_000u128 * dt as u128) / (dt as u128 + halflife_slots as u128);
        let alpha_bps = ewma_effective_alpha_bps(alpha_bps, fee_paid, mark_min_fee);
        let old128 = old as u128;
        let price128 = price as u128;
        let out = if price >= old {
            old128 + ((price128 - old128) * alpha_bps / 10_000)
        } else {
            old128 - ((old128 - price128) * alpha_bps / 10_000)
        };
        core::cmp::min(out, u64::MAX as u128) as u64
    }

    pub fn dynamic_fee_bps_with_externality_floor(
        base_fee_bps: u64,
        old_mark_e6: u64,
        clamped_exec_e6: u64,
        halflife_slots: u64,
        last_mark_slot: u64,
        now_slot: u64,
        trade_notional: u128,
        mark_externality_notional: u128,
        mark_min_fee: u64,
        min_externality_bps: u64,
    ) -> Option<u64> {
        if base_fee_bps > MAX_DYNAMIC_TRADE_FEE_BPS {
            return None;
        }
        let mut fee_bps = base_fee_bps;
        let mut i = 0;
        while i < 64 {
            let fee_paid = two_sided_trade_fee_paid_cap(trade_notional, fee_bps)?;
            let next_mark = ewma_update(
                old_mark_e6,
                clamped_exec_e6,
                halflife_slots,
                last_mark_slot,
                now_slot,
                fee_paid,
                mark_min_fee,
            );
            let mark_move_bps = price_move_bps_ceil(old_mark_e6, next_mark)?;
            let charged_move_bps = core::cmp::max(mark_move_bps, min_externality_bps);
            let base_paid = two_sided_trade_fee_paid_cap(trade_notional, base_fee_bps)? as u128;
            let mark_fee = ceil_div_u128(
                mark_externality_notional.checked_mul(charged_move_bps as u128)?,
                10_000,
            )?;
            let required = base_paid.checked_add(mark_fee)?;
            let denom = trade_notional.checked_mul(2)?;
            let needed = ceil_div_u128(required.checked_mul(10_000)?, denom)?;
            let needed = u64::try_from(needed).ok()?;
            if needed > MAX_DYNAMIC_TRADE_FEE_BPS {
                return None;
            }
            if needed <= fee_bps {
                return Some(fee_bps);
            }
            fee_bps = needed;
            i += 1;
        }
        None
    }

    /// DEPRECATED (2026-07-19 fee-collection design): tolerance constant for
    /// `fee_split_floor_ok`, which no longer has any live call sites. Retained
    /// only so that function's existing Kani proofs and unit tests keep
    /// compiling. See `fee_split_floor_ok`'s doc comment for the full
    /// rationale.
    ///
    /// Fee-split floor tolerance derivation for `fee_split_floor_ok` below
    /// (house requirement: on-chain enforcement of the launch wizard's
    /// non-protocol-remainder floors: creator at most 45%, LP at least 40%,
    /// insurance at least 15%, all of `T = trade_fee_base_bps +
    /// backing_fee_bps`; so a raw instruction can't bypass the
    /// client-side-only check in `feeSplit.ts`).
    ///
    /// The wizard computes `trade_fee_base_bps = round(T * creatorPct /
    /// 100)` and `insurance_share_bps = round(insurancePct * 10000 /
    /// (insurancePct plus lpPct))`. Both are standard round-half-up
    /// roundings of a real value, so each individual rounding error is
    /// bounded in magnitude by exactly 0.5 (in the rounded field's own
    /// units: 0.5 bps for `trade_fee_base_bps`, 0.5/10000 of the backing fee
    /// for `insurance_share_bps`). Because `backing_fee_bps` equals `T`
    /// minus `trade_fee_base_bps` as an exact integer subtraction on the
    /// client (not an independent rounding), its error is exactly the
    /// negative of `trade_fee_base_bps`'s error, also bounded by 0.5, and
    /// `T` itself (`trade_fee_base_bps + backing_fee_bps` reconstructed
    /// on-chain) is therefore always exactly the client's original integer
    /// `T`, with no accumulated error of its own.
    ///
    /// Propagating those two independent, bounded errors through each
    /// integer inequality gives worst-case constants that do NOT depend on
    /// `T` (this is a proven bound, not a value merely sized to pass one
    /// example):
    ///
    /// Creator check (`tfb times 100 <= 45 times T`): the only error source
    /// is `trade_fee_base_bps`'s own rounding, contributing at most `0.5
    /// times 100 = 50` to the LHS, giving `CREATOR_TOLERANCE = 50`.
    ///
    /// Insurance/LP checks (`bf times isb >= 15 times T times 100` and `bf
    /// times (10000 minus isb) >= 40 times T times 100`): two independent
    /// error sources. `insurance_share_bps`'s error (at most 0.5) multiplied
    /// by `backing_fee_bps` -- bounded not by its 10_000 wire-width cap but
    /// by the TIGHTER, structural `backing_fee_bps <= T` (it falls straight
    /// out of `bf = T - tfb` with `tfb` unsigned, true for ANY reachable
    /// input, not merely a caller precondition) -- contributes at most `0.5
    /// times T = T/2`, computed inline per-call as the ceiling `(t+1)/2`.
    /// `backing_fee_bps`'s error (at most 0.5) multiplied by the OTHER
    /// factor (`insurance_share_bps` or its complement, genuinely bounded by
    /// its own 10_000 range, not a looseness artifact) contributes at most
    /// `0.5 times 10000 = 5000`, folded with the negligible `0.5 times 0.5`
    /// cross term into the flat `FEE_SPLIT_SHARE_TOLERANCE_FLAT = 5_001`.
    /// The combined, T-scaled tolerance is therefore `ceil(T/2) + 5_001`
    /// (see `FEE_SPLIT_SHARE_TOLERANCE_FLAT`'s doc comment for the full
    /// derivation and the proven residual min-T carve-out this leaves: the
    /// check is a structural no-op only for insurance at T in {1,2,3} bps
    /// and LP at T=1 bps, versus T<=6/T<=2 for the old flat-10_000 bound,
    /// which incorrectly used `bf <= 10_000` -- the GLOBAL wire-width cap --
    /// in place of the tight, structural `bf <= T`).
    ///
    /// Worked edge case that exercises both tolerances at once (see
    /// `tests::fee_split_floor_*` for the executable version): the wizard's
    /// own simultaneous boundary point (creatorPct=45, lpPct=40,
    /// insurancePct=15, all three floors hit at once) at a low but
    /// realistic total fee `T=10` bps rounds to `trade_fee_base_bps=5`
    /// (ideal 4.5, rounds up: the exact 0.5 worst case), `backing_fee_bps=5`,
    /// `insurance_share_bps=2727` (ideal 2727.27...). The resulting on-chain
    /// split is ACTUALLY 50% creator, 36.365% LP, 13.635% insurance: all
    /// three floors technically violated by the rounding, yet this is
    /// exactly what the wizard's own UI produced for a legitimate boundary
    /// selection. A tolerance-free check would reject it; these proven
    /// worst-case tolerances accept it (see `fee_split_floor_ok`'s doc
    /// comment for the pass/reject values on this exact input). The
    /// wizard's default 20/60/20 example (T=20, creatorPct=20) needs no
    /// tolerance at all (passes with wide margin) and is not the case that
    /// determined these constants.
    pub const FEE_SPLIT_CREATOR_TOLERANCE: u64 = 50;

    /// T-INDEPENDENT half of the insurance/LP share tolerance (replaces the
    /// old flat `FEE_SPLIT_SHARE_TOLERANCE = 10_000`, which incorrectly
    /// bounded `backing_fee_bps`'s rounding-error contribution by its global
    /// wire-width cap (10_000) instead of by `T` -- since `bf = T - tfb`
    /// with `tfb` unsigned, `bf <= T` ALWAYS, structurally, independent of
    /// any caller precondition. Using the loose 10_000 bound made the check
    /// degenerate to a no-op at low T: `15*T*100 <= 10_000` for T<=6, so the
    /// insurance floor was fully vacuous there (`10_000 <= 40*T*100` doing
    /// the same to the LP floor for T<=2). This constant covers only the
    /// OTHER error term, `isb_ideal * e_bf` (resp. `lp_share_ideal * e_bf`),
    /// which stays flat at <=10_000*0.5=5000 regardless of T because `isb` /
    /// `lp_share = 10_000 - isb` are share-of-10_000 values independent of
    /// T's magnitude by construction (not a looseness artifact -- tightening
    /// this further requires coupling to the wizard's specific percentage
    /// floors, deliberately avoided here for robustness against future
    /// floor-value changes). +1 covers the negligible e_bf*e_isb cross term.
    /// The OTHER (T-dependent) half of the tolerance, covering
    /// `bf_ideal * e_isb` now bounded via the structural `bf_ideal <= T`
    /// instead of `bf_ideal <= 10_000`, is computed inline as `(t + 1) / 2`
    /// at each call site below -- integer ceiling-division by the
    /// compile-time constant 2, never by `t`, so no div-by-zero guard is
    /// needed (t==0 is already short-circuited above this code).
    ///
    /// Residual carve-out (proven, not incidental): even with this tighter,
    /// T-scaled tolerance, the check is still a structural no-op for
    /// insurance at T in {1,2,3} bps and for LP at T=1 bps -- down from the
    /// old bug's T<=6 / T<=2, but not eliminable further without coupling to
    /// the wizard's specific percentage floors: at T=1..3 bps, `isb`'s own
    /// rounding error alone (<=0.5*10_000=5000) already exceeds the entire
    /// target quantity (`1500*T <= 4500` at T=3). This mirrors the
    /// function's own pre-existing, deliberate `backing_fee_bps==0` skip,
    /// just at a narrower boundary; closing it fully would require a
    /// frontend-side minimum-T guard in the wizard, out of scope here.
    pub const FEE_SPLIT_SHARE_TOLERANCE_FLAT: u128 = 5_001;

    /// DEPRECATED (2026-07-19 fee-collection design): validated a two-rate
    /// split (`T = trade_fee_base_bps + backing_fee_bps`) that no longer
    /// exists. Superseded by `validate_fee_split`, which is exact rather than
    /// tolerance-based and has no `backing_fee_bps == 0` skip path -- that
    /// skip meant this check never actually ran on a live market, since
    /// `backing_trade_fee_bps` is 0 on every deployed market. Retained so its
    /// existing proofs and tests keep compiling; NO LIVE CALL SITES REMAIN.
    /// The historical description below is preserved for those proofs.
    ///
    /// Joint on-chain floor check for the launch wizard's fee-split
    /// invariant (creator <=45%, LP >=40%, insurance >=15% of `T =
    /// trade_fee_base_bps + backing_fee_bps`), formerly applied by both
    /// `UpdateBackingFeePolicy` and `UpdateTradeFeePolicy`'s handlers.
    ///
    /// Skips entirely (returns `true`) when `backing_fee_bps == 0` --
    /// backing fee not yet configured (e.g. immediately after `InitMarket`,
    /// or a legitimate all-creator config) -- the three-way split isn't
    /// complete yet, so no floor applies. Callers must separately keep
    /// enforcing any pre-existing `insurance_share_bps == 0` requirement for
    /// that state (see `backing_trade_fee_policy_shape_ok`); this function
    /// does not duplicate that check.
    ///
    /// Deliberately NOT wired into `validate_wrapper_config` /
    /// `backing_trade_fee_policy_shape_ok` / `validate_asset_oracle_profile`
    /// (the load-time shape validators run on every deserialize of an
    /// existing market's config/profile -- see call sites at
    /// `read_wrapper_config_from_bytes` /
    /// `read_wrapper_config_boxed_from_bytes` / wherever
    /// `validate_asset_oracle_profile` is invoked). Putting a floor check
    /// there would retroactively brick every market created before this
    /// change whose stored split doesn't satisfy the new floor -- this
    /// function is called ONLY from the two setter handlers, at the moment
    /// a new split is being written.
    ///
    /// All inputs are raw on-chain bps fields; callers must already
    /// range-check them to <=10_000 (`trade_fee_base_bps` additionally
    /// <=`MAX_DYNAMIC_TRADE_FEE_BPS`) before calling this -- it does not
    /// re-validate that shape, only the joint floor. Pure, no side effects,
    /// safe to call from Kani proofs and unit tests.
    ///
    /// The "called ONLY from the two setter handlers" sentence above is
    /// HISTORICAL and no longer true — see the RETIRED banner on the
    /// declaration below. It is left in place because it documents the
    /// reasoning that produced the function.
    #[deprecated(
        note = "RETIRED: no live call sites. `2b3a6a65` removed this from \
                handle_update_backing_fee_policy / handle_update_trade_fee_policy. \
                Live fee-split floors are enforced by `validate_fee_split`, called \
                from `handle_update_fee_split` (tag 86). Retained only so its Kani \
                proof and unit tests still compile."
    )]
    pub fn fee_split_floor_ok(
        trade_fee_base_bps: u64,
        backing_fee_bps: u64,
        insurance_share_bps: u64,
    ) -> bool {
        if backing_fee_bps == 0 {
            return true;
        }
        let tfb = trade_fee_base_bps as u128;
        let bf = backing_fee_bps as u128;
        let isb = insurance_share_bps as u128;
        let lp_share = match 10_000u128.checked_sub(isb) {
            Some(v) => v,
            None => return false,
        };
        let t = match tfb.checked_add(bf) {
            Some(v) => v,
            None => return false,
        };
        if t == 0 {
            return true;
        }

        // creator% <= 45  <=>  tfb*100 <= 45*T (+ tolerance)
        let creator_lhs = match tfb.checked_mul(100) {
            Some(v) => v,
            None => return false,
        };
        let creator_rhs = match t
            .checked_mul(45)
            .and_then(|v| v.checked_add(FEE_SPLIT_CREATOR_TOLERANCE as u128))
        {
            Some(v) => v,
            None => return false,
        };
        if creator_lhs > creator_rhs {
            return false;
        }

        // T-scaled tolerance shared by the insurance and LP checks below
        // (both use the same bound: bf<=T structural + isb/lp_share<=10_000
        // structural -- see FEE_SPLIT_SHARE_TOLERANCE_FLAT's doc comment).
        let t_half_ceil = match t.checked_add(1) {
            Some(v) => v / 2, // safe: divides by the constant 2, not by t
            None => return false,
        };
        let share_tolerance = match t_half_ceil.checked_add(FEE_SPLIT_SHARE_TOLERANCE_FLAT) {
            Some(v) => v,
            None => return false,
        };

        // insurance% >= 15  <=>  bf*isb >= 15*T*100 (- tolerance)
        let insurance_lhs = match bf.checked_mul(isb) {
            Some(v) => v,
            None => return false,
        };
        let insurance_rhs_exact = match t.checked_mul(1_500) {
            Some(v) => v,
            None => return false,
        };
        let insurance_rhs = insurance_rhs_exact.saturating_sub(share_tolerance);
        if insurance_lhs < insurance_rhs {
            return false;
        }

        // lp% >= 40  <=>  bf*(10000-isb) >= 40*T*100 (- tolerance)
        let lp_lhs = match bf.checked_mul(lp_share) {
            Some(v) => v,
            None => return false,
        };
        let lp_rhs_exact = match t.checked_mul(4_000) {
            Some(v) => v,
            None => return false,
        };
        let lp_rhs = lp_rhs_exact.saturating_sub(share_tolerance);
        if lp_lhs < lp_rhs {
            return false;
        }

        true
    }

    /// Exact four-way split of a trade fee (2026-07-19 fee-collection design).
    ///
    /// Each leg is `floor(fee * share_bps / 10_000)`; the residual dust is
    /// assigned to `insurance` — the most conservative destination, since it
    /// grows the backstop rather than anyone's withdrawable revenue.
    ///
    /// CONSERVATION INVARIANT (Kani-proven, `kani_fee_split_conserves`):
    ///   protocol + creator + lp + insurance == fee, for every input.
    /// Violating it desyncs `header.insurance` and the vault accounting with it.
    ///
    /// Takes plain bps rather than `&WrapperConfigV16` so it stays free of the
    /// zero-copy type and is directly Kani-provable (same rationale as
    /// `maintenance_cranker_reward`).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FeeSplitParts {
        pub protocol: u128,
        pub creator: u128,
        pub lp: u128,
        pub insurance: u128,
    }

    pub fn split_trade_fee(
        fee: u128,
        protocol_bps: u16,
        creator_bps: u16,
        lp_bps: u16,
        insurance_bps: u16,
    ) -> Result<FeeSplitParts, ProgramError> {
        if fee == 0 {
            return Ok(FeeSplitParts::default());
        }
        let cut = |bps: u16| -> Result<u128, ProgramError> {
            fee.checked_mul(bps as u128)
                .map(|v| v / 10_000)
                .ok_or_else(|| PercolatorError::EngineArithmeticOverflow.into())
        };
        let protocol = cut(protocol_bps)?;
        let creator = cut(creator_bps)?;
        let lp = cut(lp_bps)?;
        // Insurance takes its floor share PLUS all residual dust, so the four
        // parts sum to exactly `fee` regardless of rounding.
        let assigned = protocol
            .checked_add(creator)
            .and_then(|v| v.checked_add(lp))
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let insurance = fee
            .checked_sub(assigned)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        Ok(FeeSplitParts { protocol, creator, lp, insurance })
    }

    /// Exact fee-split validation for `UpdateFeeSplit` (2026-07-19 design).
    ///
    /// Replaces `fee_split_floor_ok`'s tolerance-based two-rate check: with a
    /// single rate there is no cross-rate rounding to absorb, so this is an
    /// exact integer comparison with no tolerance and no skip path.
    ///
    /// Returns Ok(()) or the specific error. MUST be called ONLY from the
    /// UpdateFeeSplit handler -- never from a load-time validator, because
    /// `validate_wrapper_config` runs on every deserialize and a floor there
    /// would retroactively brick markets whose stored split predates it.
    pub fn validate_fee_split(
        creator_bps: u16,
        lp_bps: u16,
        insurance_bps: u16,
    ) -> Result<(), ProgramError> {
        let sum = creator_bps as u32 + lp_bps as u32 + insurance_bps as u32;
        if sum != FEE_SHARE_TOTAL_BPS as u32 {
            return Err(PercolatorError::FeeSplitSumInvalid.into());
        }
        if creator_bps > MAX_CREATOR_SHARE_BPS
            || lp_bps < MIN_LP_SHARE_BPS
            || insurance_bps < MIN_INSURANCE_SHARE_BPS
        {
            return Err(PercolatorError::FeeSplitFloorViolation.into());
        }
        Ok(())
    }
}

pub mod processor {
    use super::*;
    use crate::{
        error::{map_v16_error, PercolatorError},
        ix::Instruction,
        state::{self, WrapperConfigV16},
    };

    // The market-level authority is now a single `marketauth` key rotated via UpdateAuthority
    // (tag 32) with no `kind` discriminant, so the former AUTHORITY_* market-kind constants are gone.

    // Per-asset authority kinds (UpdateAssetAuthority), scoped to a single permissionless asset's profile.
    pub const ASSET_AUTH_ADMIN: u8 = 0;
    pub const ASSET_AUTH_INSURANCE: u8 = 1;
    pub const ASSET_AUTH_INSURANCE_OPERATOR: u8 = 2;
    pub const ASSET_AUTH_BACKING_BUCKET: u8 = 3;
    pub const ASSET_AUTH_ORACLE: u8 = 4;

    pub const ASSET_ACTION_ACTIVATE: u8 = 0;
    pub const ASSET_ACTION_DRAIN_ONLY: u8 = 1;
    pub const ASSET_ACTION_RETIRE: u8 = 2;
    pub const ASSET_ACTION_SHUTDOWN: u8 = 3;
    const ASSET_LIFECYCLE_ACTIVE: u8 = 2;
    const ASSET_LIFECYCLE_DRAIN_ONLY: u8 = 3;
    const ASSET_LIFECYCLE_RETIRED: u8 = 4;
    const ASSET_LIFECYCLE_RECOVERY: u8 = 5;

    fn authenticated_slot_or_fallback(fallback_slot: u64) -> u64 {
        Clock::get().map(|c| c.slot).unwrap_or(fallback_slot)
    }

    /// Warn, at creation time, when the configured price/rate/dt combination
    /// makes the engine's funding accrual floor to zero on every crank.
    ///
    /// The engine books, per accrual segment:
    ///
    /// ```text
    /// fund_num_total = floor(rate_e9 * segment_dt * effective_price / FUNDING_DEN)
    /// ```
    ///
    /// with `FUNDING_DEN == 1e9`, `|rate_e9| <= max_abs_funding_e9_per_slot`
    /// and `segment_dt <= max_accrual_dt_slots`. The best case this market can
    /// reach at price `p` is `rate * dt * p`; when that is `< FUNDING_DEN` the
    /// floor is 0 for every crank and the market has a funding *setting* with
    /// no funding *mechanism* — silently, with no error at trade time.
    ///
    /// Equivalently, funding needs `price >= ceil(1e9 / (rate * dt))`. At the
    /// engine's maximum legal rate (10_000) with `dt = 100` that is price 1000;
    /// at `dt = 5` it is price 20_000. A market denominated in small integers
    /// cannot fund.
    ///
    /// WHY THIS WARNS RATHER THAN REJECTS. The condition is a property of the
    /// *current price*, and price is mutable: a market created at price 999 is
    /// dead-funded at genesis but funds correctly once it trades above the
    /// threshold, so rejecting on the genesis price would refuse markets that
    /// are merely dead *now*, not *forever*. The one condition that IS
    /// permanent — funding impossible at every legal price, i.e.
    /// `rate * dt * MAX_ORACLE_PRICE < FUNDING_DEN` — is unreachable for any
    /// integer `rate >= 1, dt >= 1` given `MAX_ORACLE_PRICE == 1e12`, so a
    /// hard reject would either be dead code or would over-reject. The honest
    /// program-side maximum is therefore a loud, specific creation-time log
    /// naming the price the creator needs, for the SDK / launch wizard to
    /// surface. This is a WARNING, not a repair: the arithmetic is in the
    /// engine and is deliberately not changed.
    ///
    /// Markets that disable funding (`max_abs == 0`) are silent — they are not
    /// broken, they are explicitly off. `dt == 0` is left to the engine's own
    /// config validation rather than being re-judged here.
    fn warn_if_funding_cannot_accrue(
        max_abs_funding_e9_per_slot: u64,
        max_accrual_dt_slots: u64,
        initial_price: u64,
    ) {
        if max_abs_funding_e9_per_slot == 0 || max_accrual_dt_slots == 0 || initial_price == 0 {
            return;
        }
        let rate_times_dt = (max_abs_funding_e9_per_slot as u128)
            .saturating_mul(max_accrual_dt_slots as u128);
        let best_case = rate_times_dt.saturating_mul(initial_price as u128);
        if best_case >= percolator::FUNDING_DEN {
            return;
        }
        // ceil(FUNDING_DEN / (rate * dt)) — the lowest price at which a full
        // accrual window at the maximum configured rate books one funding atom.
        let threshold = percolator::FUNDING_DEN.div_ceil(rate_times_dt);
        // `alloc::format!` (this crate is `no_std` + `extern crate alloc`), and
        // only on the warn path, so the allocation costs nothing on the
        // overwhelmingly common healthy configuration.
        solana_program::log::sol_log(&alloc::format!(
            "WARN funding-cannot-accrue: price {initial_price} < threshold {threshold} \
             for rate {max_abs_funding_e9_per_slot} x dt {max_accrual_dt_slots}; \
             floor(rate*dt*price/1e9) == 0 on every crank, so funding will never accrue \
             until price reaches the threshold"
        ));
    }

    fn authenticated_market_slot_or_fallback_view(group: &state::MarketViewMutV16<'_>) -> u64 {
        core::cmp::max(
            Clock::get()
                .map(|c| c.slot)
                .unwrap_or(group.header.current_slot.get()),
            group.header.current_slot.get(),
        )
    }

    fn decode_side(value: u8) -> Result<SideV16, ProgramError> {
        match value {
            0 => Ok(SideV16::Long),
            1 => Ok(SideV16::Short),
            _ => Err(PercolatorError::InvalidInstruction.into()),
        }
    }

    #[inline(always)]
    fn permissionless_market_init_fee_for_asset(
        base_fee: u128,
        asset_index: usize,
    ) -> Result<u128, ProgramError> {
        let mut fee = base_fee;
        if fee == 0 {
            return Ok(0);
        }
        let mut doublings = asset_index / 32;
        while doublings != 0 {
            fee = fee
                .checked_mul(2)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            doublings -= 1;
        }
        Ok(fee)
    }

    fn permissionless_resolve_matured_now_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
    ) -> bool {
        oracle_v16::permissionless_stale_matured(
            cfg,
            authenticated_market_slot_or_fallback_view(group),
        )
    }

    fn global_or_profile_resolve_matured_at_slot(
        cfg: &WrapperConfigV16,
        profile: &state::AssetOracleProfileV16,
        now_slot: u64,
    ) -> bool {
        oracle_v16::permissionless_stale_matured(cfg, now_slot)
            || (oracle_v16::profile_is_price_managed(profile)
                && cfg.permissionless_resolve_stale_slots != 0
                && profile.last_good_oracle_slot != 0
                && now_slot.saturating_sub(profile.last_good_oracle_slot)
                    >= cfg.permissionless_resolve_stale_slots)
    }

    fn reject_permissionless_resolve_matured_live_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
    ) -> ProgramResult {
        if group.header.mode == 0 && permissionless_resolve_matured_now_view(cfg, group) {
            return Err(PercolatorError::OracleStale.into());
        }
        Ok(())
    }

    fn reject_permissionless_resolve_matured_live_for_profile_view(
        cfg: &WrapperConfigV16,
        profile: &state::AssetOracleProfileV16,
        group: &state::MarketViewMutV16<'_>,
    ) -> ProgramResult {
        if group.header.mode == 0
            && global_or_profile_resolve_matured_at_slot(
                cfg,
                profile,
                authenticated_market_slot_or_fallback_view(group),
            )
        {
            return Err(PercolatorError::OracleStale.into());
        }
        Ok(())
    }

    fn shutdown_asset_matured_at_slot_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        now_slot: u64,
    ) -> ProgramResult {
        if group.header.mode != 0
            || asset_index == 0
            || cfg.force_close_delay_slots == 0
            || asset_index >= group.header.config.max_market_slots.get() as usize
            || asset_index >= group.markets.len()
            || group.markets[asset_index].engine.asset.lifecycle != ASSET_LIFECYCLE_RECOVERY
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let profile = read_oracle_profile_from_view(group, cfg, asset_index)?;
        let shutdown_slot = profile.last_good_oracle_slot;
        if shutdown_slot == 0
            || now_slot < shutdown_slot
            || now_slot.saturating_sub(shutdown_slot) < cfg.force_close_delay_slots
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        Ok(())
    }

    fn shutdown_asset_empty_and_matured_at_slot_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        now_slot: u64,
    ) -> ProgramResult {
        shutdown_asset_matured_at_slot_view(cfg, group, asset_index, now_slot)?;
        if asset_local_has_position_or_loss_state_view(group, asset_index) {
            return Err(PercolatorError::EngineLockActive.into());
        }
        Ok(())
    }

    fn shutdown_asset_empty_and_matured_now_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> ProgramResult {
        let now_slot = authenticated_market_slot_or_fallback_view(group);
        shutdown_asset_empty_and_matured_at_slot_view(cfg, group, asset_index, now_slot)
    }

    fn live_domain_withdraw_health_or_shutdown_view(
        cfg: &WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> Result<bool, ProgramError> {
        let asset_index = domain / 2;
        if shutdown_asset_empty_and_matured_now_view(cfg, group, asset_index).is_ok() {
            return Ok(true);
        }
        reject_permissionless_resolve_matured_live_view(cfg, group)?;
        if group.header.bankruptcy_hlock_active != 0
            || group.header.threshold_stress_active != 0
            || group.header.loss_stale_active != 0
            || group
                .header
                .recovery_reason
                .try_to_runtime()
                .map_err(map_v16_error)?
                .is_some()
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if asset_local_loss_stale_view(group, asset_index) {
            return Err(PercolatorError::EngineLockActive.into());
        }
        reject_exposed_target_effective_lag_view(group, asset_index)?;
        Ok(false)
    }

    fn asset_local_loss_stale_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> bool {
        if asset_index >= group.header.config.max_market_slots.get() as usize
            || asset_index >= group.markets.len()
        {
            return true;
        }
        let asset = &group.markets[asset_index].engine.asset;
        matches!(
            asset.lifecycle,
            ASSET_LIFECYCLE_ACTIVE | ASSET_LIFECYCLE_DRAIN_ONLY
        ) && asset.slot_last.get() < group.header.current_slot.get()
            && asset_local_has_position_or_loss_state_view(group, asset_index)
    }

    fn asset_has_exposed_target_effective_lag_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> Result<bool, ProgramError> {
        let slot = group
            .markets
            .get(asset_index)
            .ok_or(PercolatorError::InvalidInstruction)?;
        let asset = &slot.engine.asset;
        let exposed = asset.oi_eff_long_q.get() != 0 || asset.oi_eff_short_q.get() != 0;
        Ok(exposed && asset.raw_oracle_target_price.get() != asset.effective_price.get())
    }

    fn reject_exposed_target_effective_lag_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> ProgramResult {
        if asset_has_exposed_target_effective_lag_view(group, asset_index)? {
            return Err(PercolatorError::EngineLockActive.into());
        }
        Ok(())
    }

    fn read_oracle_profile_for_asset(
        market_data: &[u8],
        cfg: &WrapperConfigV16,
        asset_index: usize,
    ) -> Result<state::AssetOracleProfileV16, ProgramError> {
        let _ = cfg;
        state::read_asset_oracle_profile(market_data, asset_index)
    }

    fn read_oracle_profile_from_view(
        group: &state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        asset_index: usize,
    ) -> Result<state::AssetOracleProfileV16, ProgramError> {
        let _ = cfg;
        let market = group
            .markets
            .get(asset_index)
            .ok_or(PercolatorError::InvalidInstruction)?;
        let bytes = market
            .wrapper
            .get(..constants::ASSET_ORACLE_PROFILE_LEN)
            .ok_or(PercolatorError::InvalidAccountLen)?;
        let profile: state::AssetOracleProfileV16 = bytemuck::pod_read_unaligned(bytes);
        state::validate_asset_oracle_profile(&profile)?;
        Ok(profile)
    }

    fn write_oracle_profile_to_view_if_separate(
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
        profile: &state::AssetOracleProfileV16,
    ) -> ProgramResult {
        if asset_index != 0 {
            write_oracle_profile_to_view(group, asset_index, profile)?;
        }
        Ok(())
    }

    fn write_oracle_profile_to_view(
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
        profile: &state::AssetOracleProfileV16,
    ) -> ProgramResult {
        state::validate_asset_oracle_profile(profile)?;
        let market = group
            .markets
            .get_mut(asset_index)
            .ok_or(PercolatorError::InvalidInstruction)?;
        market.wrapper[..constants::ASSET_ORACLE_PROFILE_LEN]
            .copy_from_slice(bytemuck::bytes_of(profile));
        Ok(())
    }

    fn mirror_manual_profile_to_base_config(
        cfg: &mut WrapperConfigV16,
        profile: &state::AssetOracleProfileV16,
        refresh_liveness: bool,
    ) {
        cfg.oracle_mode = constants::ORACLE_MODE_MANUAL;
        cfg.oracle_leg_count = 0;
        cfg.oracle_leg_flags = 0;
        cfg.invert = 0;
        cfg.unit_scale = 0;
        cfg.conf_filter_bps = 0;
        cfg.max_staleness_secs = 0;
        cfg.hybrid_soft_stale_slots = 0;
        cfg.mark_ewma_e6 = profile.mark_ewma_e6;
        cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
        cfg.mark_ewma_halflife_slots = profile.mark_ewma_halflife_slots;
        cfg.mark_min_fee = 0;
        cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
        cfg.oracle_target_publish_time = 0;
        if refresh_liveness {
            cfg.last_good_oracle_slot = profile.last_good_oracle_slot;
        }
        cfg.oracle_leg_feeds = [[0u8; 32]; constants::ORACLE_LEG_CAP];
        cfg.oracle_leg_prices_e6 = [0u64; constants::ORACLE_LEG_CAP];
        cfg.oracle_leg_publish_times = [0i64; constants::ORACLE_LEG_CAP];
    }

    fn preserve_backing_fee_policy(
        mut profile: state::AssetOracleProfileV16,
        existing: &state::AssetOracleProfileV16,
    ) -> state::AssetOracleProfileV16 {
        profile.backing_trade_fee_bps_long = existing.backing_trade_fee_bps_long;
        profile.backing_trade_fee_bps_short = existing.backing_trade_fee_bps_short;
        profile.backing_trade_fee_insurance_share_bps_long =
            existing.backing_trade_fee_insurance_share_bps_long;
        profile.backing_trade_fee_insurance_share_bps_short =
            existing.backing_trade_fee_insurance_share_bps_short;
        profile.insurance_authority = existing.insurance_authority;
        profile.insurance_operator = existing.insurance_operator;
        profile.backing_bucket_authority = existing.backing_bucket_authority;
        profile.oracle_authority = existing.oracle_authority;
        profile
    }

    fn backing_fee_policy_count_from_profile(profile: &state::AssetOracleProfileV16) -> u16 {
        (profile.backing_trade_fee_bps_long != 0) as u16
            + (profile.backing_trade_fee_bps_short != 0) as u16
    }

    fn add_backing_fee_policy_count(cfg: &mut WrapperConfigV16, count: u16) -> ProgramResult {
        if count != 0 {
            cfg.backing_trade_fee_policy_count = cfg
                .backing_trade_fee_policy_count
                .checked_add(count)
                .ok_or(PercolatorError::EngineCounterOverflow)?;
        }
        Ok(())
    }

    fn subtract_backing_fee_policy_count(cfg: &mut WrapperConfigV16, count: u16) -> ProgramResult {
        if count != 0 {
            cfg.backing_trade_fee_policy_count = cfg
                .backing_trade_fee_policy_count
                .checked_sub(count)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
        }
        Ok(())
    }

    fn domain_authority_fields_complete(
        insurance_authority: [u8; 32],
        insurance_operator: [u8; 32],
        backing_bucket_authority: [u8; 32],
        oracle_authority: [u8; 32],
    ) -> bool {
        insurance_authority != [0u8; 32]
            && insurance_operator != [0u8; 32]
            && backing_bucket_authority != [0u8; 32]
            && oracle_authority != [0u8; 32]
    }

    #[derive(Clone, Copy)]
    struct DomainAuthoritiesV16 {
        insurance_authority: [u8; 32],
        insurance_operator: [u8; 32],
        backing_bucket_authority: [u8; 32],
        oracle_authority: [u8; 32],
    }

    fn domain_authorities_from_profile(
        cfg: &WrapperConfigV16,
        profile: &state::AssetOracleProfileV16,
        asset_index: usize,
    ) -> DomainAuthoritiesV16 {
        let _ = (cfg, asset_index);
        DomainAuthoritiesV16 {
            insurance_authority: profile.insurance_authority,
            insurance_operator: profile.insurance_operator,
            backing_bucket_authority: profile.backing_bucket_authority,
            oracle_authority: profile.oracle_authority,
        }
    }

    fn domain_authorities_from_view(
        group: &state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        domain: usize,
    ) -> Result<DomainAuthoritiesV16, ProgramError> {
        let asset_index = domain / 2;
        if domain >= (group.header.config.max_market_slots.get() as usize).saturating_mul(2)
            || asset_index >= group.markets.len()
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let profile = read_oracle_profile_from_view(group, cfg, asset_index)?;
        Ok(domain_authorities_from_profile(cfg, &profile, asset_index))
    }

    fn require_domain_accepts_live_topup_view(
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> ProgramResult {
        let asset_index = domain / 2;
        if domain >= (group.header.config.max_market_slots.get() as usize).saturating_mul(2)
            || asset_index >= group.markets.len()
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        match group.markets[asset_index].engine.asset.lifecycle {
            ASSET_LIFECYCLE_ACTIVE | ASSET_LIFECYCLE_DRAIN_ONLY | ASSET_LIFECYCLE_RECOVERY => {
                Ok(())
            }
            _ => Err(PercolatorError::EngineLockActive.into()),
        }
    }

    fn domain_budget_remaining_view(
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> Result<u128, ProgramError> {
        group
            .domain_insurance_budget_remaining(domain)
            .map_err(map_v16_error)
    }

    fn domain_withdraw_capacity_view(
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> Result<u128, ProgramError> {
        group
            .domain_insurance_withdraw_capacity(domain)
            .map_err(map_v16_error)
    }

    fn credit_market_insurance_budget_view(
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
        amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        let long_amount = amount / 2;
        let short_amount = amount
            .checked_sub(long_amount)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        group
            .credit_domain_insurance_budget_not_atomic(asset_index * 2, long_amount)
            .map_err(map_v16_error)?;
        group
            .credit_domain_insurance_budget_not_atomic(asset_index * 2 + 1, short_amount)
            .map_err(map_v16_error)
    }

    fn deposit_market_zero_insurance_view(
        group: &mut state::MarketViewMutV16<'_>,
        amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        let long_amount = amount / 2;
        let short_amount = amount
            .checked_sub(long_amount)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        group
            .deposit_domain_insurance_not_atomic(0, long_amount)
            .map_err(map_v16_error)?;
        group
            .deposit_domain_insurance_not_atomic(1, short_amount)
            .map_err(map_v16_error)
    }

    fn market_insurance_remaining_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> Result<u128, ProgramError> {
        let long = domain_budget_remaining_view(group, asset_index * 2)?;
        let short = domain_budget_remaining_view(group, asset_index * 2 + 1)?;
        let budget = long
            .checked_add(short)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(budget.min(group.header.insurance.get()))
    }

    fn market_insurance_withdraw_capacity_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> Result<u128, ProgramError> {
        let long = domain_withdraw_capacity_view(group, asset_index * 2)?;
        let short = domain_withdraw_capacity_view(group, asset_index * 2 + 1)?;
        let capacity = long
            .checked_add(short)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let global_available = group.header.insurance.get().saturating_sub(
            group
                .header
                .source_insurance_credit_reserved_total_atoms
                .get(),
        );
        Ok(capacity.min(global_available).min(group.header.vault.get()))
    }

    fn terminal_insurance_withdraw_capacity_for_authority_view(
        group: &state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        authority: &Pubkey,
    ) -> Result<u128, ProgramError> {
        let authority_bytes = authority.to_bytes();
        if authority_bytes == [0u8; 32] {
            return Err(PercolatorError::Unauthorized.into());
        }
        let domain_count = (group.header.config.max_market_slots.get() as usize)
            .checked_mul(2)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let mut total = 0u128;
        let mut domain = 0usize;
        while domain < domain_count {
            let authorities = domain_authorities_from_view(group, cfg, domain)?;
            if authorities.insurance_authority == authority_bytes {
                total = total
                    .checked_add(domain_withdraw_capacity_view(group, domain)?)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            }
            domain += 1;
        }
        let global_available = group.header.insurance.get().saturating_sub(
            group
                .header
                .source_insurance_credit_reserved_total_atoms
                .get(),
        );
        Ok(total.min(global_available).min(group.header.vault.get()))
    }

    fn debit_terminal_insurance_budgets_for_authority_view(
        group: &mut state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        authority: &Pubkey,
        mut amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        let authority_bytes = authority.to_bytes();
        if authority_bytes == [0u8; 32] {
            return Err(PercolatorError::Unauthorized.into());
        }
        let domain_count = (group.header.config.max_market_slots.get() as usize)
            .checked_mul(2)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let mut domain = 0usize;
        while domain < domain_count && amount != 0 {
            let authorities = domain_authorities_from_view(group, cfg, domain)?;
            if authorities.insurance_authority == authority_bytes {
                let remaining = domain_withdraw_capacity_view(group, domain)?;
                let debit = remaining.min(amount);
                if debit != 0 {
                    // Atomic insurance/vault/budget withdraw per domain (maintains the budget total).
                    group
                        .withdraw_domain_insurance_not_atomic(domain, debit)
                        .map_err(map_v16_error)?;
                    amount = amount
                        .checked_sub(debit)
                        .ok_or(PercolatorError::EngineCounterUnderflow)?;
                }
            }
            domain += 1;
        }
        if amount != 0 {
            return Err(PercolatorError::EngineCounterUnderflow.into());
        }
        Ok(())
    }

    fn debit_market_insurance_budget_view(
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
        mut amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        let long_domain = asset_index * 2;
        let short_domain = long_domain + 1;
        let long_remaining = domain_withdraw_capacity_view(group, long_domain)?;
        let long_debit = long_remaining.min(amount);
        if long_debit != 0 {
            group
                .withdraw_domain_insurance_not_atomic(long_domain, long_debit)
                .map_err(map_v16_error)?;
            amount = amount
                .checked_sub(long_debit)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
        }
        if amount != 0 {
            let short_remaining = domain_withdraw_capacity_view(group, short_domain)?;
            if amount > short_remaining {
                return Err(PercolatorError::EngineCounterUnderflow.into());
            }
            group
                .withdraw_domain_insurance_not_atomic(short_domain, amount)
                .map_err(map_v16_error)?;
        }
        Ok(())
    }

    // REMOVED (creator fee claim, 2026-07-23): `credit_fee_to_domain_budget_view`
    // and its only wrapper `credit_trade_fees_to_market_budgets_view`.
    //
    // Every caller of them carried the CREATOR leg of `split_trade_fee` (single
    // trade: `split_a.creator`/`split_b.creator`; batch: `split_leg.creator`),
    // so once that leg was re-routed to `cfg.creator_fee_claimable_atoms` both
    // functions had zero live callers. They dripped creator revenue into the
    // per-domain insurance budget -- the engine's loss backstop -- which is what
    // made a "claim fees" button a "drain the backstop" button.
    //
    // The `fee_redirect_to_market_0_bps` skim they applied is NOT lost: the
    // maintenance-fee and backing-fee paths still use it via
    // `credit_market_fee_split_across_domains_view` below. It simply no longer
    // applies to the creator trade-fee leg, which is now a market-level counter
    // with no per-asset domain to redirect between.

    fn credit_market_fee_split_across_domains_view(
        cfg: &WrapperConfigV16,
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
        amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        let redirect = if asset_index == 0 {
            0
        } else {
            fee_share_floor(amount, cfg.fee_redirect_to_market_0_bps)?
        };
        let domain_amount = amount
            .checked_sub(redirect)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        credit_market_insurance_budget_view(group, asset_index, domain_amount)?;
        credit_market_insurance_budget_view(group, 0, redirect)
    }

    fn credit_maintenance_fee_to_active_market_budgets_view(
        cfg: &WrapperConfigV16,
        group: &mut state::MarketViewMutV16<'_>,
        amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Ok(());
        }
        // FIX #113 (permissionless cross-asset maintenance-fee siphon): the maintenance fee is an
        // ACCOUNT-level charge (maintenance_fee_per_slot * elapsed), not tied to any asset's activity.
        // The previous logic split it equally across every ACTIVE asset's insurance domain, so a
        // permissionless attacker could append a do-nothing asset (itself as insurance_operator) and
        // siphon 1/N of every honest trader's maintenance fee via WithdrawInsuranceAsset (k/(k+1) with
        // k parasites). Credit it solely to asset-0 (the canonical base insurance, which cannot be
        // permissionlessly created): a zero-activity asset now earns nothing. This also makes the path
        // O(1) in N — the per-active-asset loop was the wrapper's only per-instruction O(N)-in-
        // max_market_slots cost, which a parasite-append bloat could push over the CU limit, bricking
        // SyncMaintenanceFee/CloseResolved and the market's eventual closability.
        let _ = cfg;
        credit_market_insurance_budget_view(group, 0, amount)
    }

    fn require_asset_active_for_oracle_reconfiguration_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> ProgramResult {
        if asset_index >= group.markets.len()
            || group.markets[asset_index].engine.asset.lifecycle != 2
            || asset_local_has_position_or_loss_state_view(group, asset_index)
            || group.header.pnl_pos_tot.get() != 0
            || group.header.stale_certificate_count.get() != 0
            || group.header.b_stale_account_count.get() != 0
            || group.header.negative_pnl_account_count.get() != 0
            || group.header.bankruptcy_hlock_active != 0
            || group.header.threshold_stress_active != 0
            || group.header.loss_stale_active != 0
            || group
                .header
                .recovery_reason
                .try_to_runtime()
                .map_err(map_v16_error)?
                .is_some()
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        Ok(())
    }

    fn require_asset_mark_pushable_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> ProgramResult {
        if asset_index >= group.markets.len() {
            return Err(PercolatorError::EngineLockActive.into());
        }
        match group.markets[asset_index].engine.asset.lifecycle {
            2 | 3 => Ok(()),
            _ => Err(PercolatorError::EngineLockActive.into()),
        }
    }

    pub fn process_instruction<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        instruction_data: &[u8],
    ) -> ProgramResult {
        match Instruction::decode(instruction_data)? {
            Instruction::InitMarket {
                max_portfolio_assets,
                h_min,
                h_max,
                initial_price,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                maintenance_margin_bps,
                initial_margin_bps,
                max_trading_fee_bps,
                trade_fee_base_bps,
                liquidation_fee_bps,
                liquidation_fee_cap,
                min_liquidation_abs,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                max_account_b_settlement_chunks,
                max_bankrupt_close_chunks,
                max_bankrupt_close_lifetime_slots,
                public_b_chunk_atoms,
                maintenance_fee_per_slot,
            } => handle_init_market(
                program_id,
                accounts,
                max_portfolio_assets,
                h_min,
                h_max,
                initial_price,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                maintenance_margin_bps,
                initial_margin_bps,
                max_trading_fee_bps,
                trade_fee_base_bps,
                liquidation_fee_bps,
                liquidation_fee_cap,
                min_liquidation_abs,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                max_account_b_settlement_chunks,
                max_bankrupt_close_chunks,
                max_bankrupt_close_lifetime_slots,
                public_b_chunk_atoms,
                maintenance_fee_per_slot,
            ),
            Instruction::InitPortfolio => handle_init_portfolio(program_id, accounts),
            Instruction::Deposit { amount } => handle_deposit(program_id, accounts, amount),
            Instruction::Withdraw { amount } => handle_withdraw(program_id, accounts, amount),
            Instruction::PermissionlessCrank {
                action,
                asset_index,
                now_slot,
                funding_rate_e9,
                recovery_reason,
            } => handle_permissionless_crank(
                program_id,
                accounts,
                action,
                asset_index,
                now_slot,
                funding_rate_e9,
                recovery_reason,
            ),
            Instruction::TradeNoCpi {
                asset_index,
                size_q,
                exec_price,
                fee_bps,
            } => handle_trade_nocpi(
                program_id,
                accounts,
                asset_index,
                size_q,
                exec_price,
                fee_bps,
            ),
            Instruction::TradeCpi {
                asset_index,
                size_q,
                fee_bps,
                limit_price,
            } => handle_trade_cpi(
                program_id,
                accounts,
                asset_index,
                size_q,
                fee_bps,
                limit_price,
            ),
            Instruction::BatchTradeNoCpi { legs } => {
                handle_batch_trade_nocpi(program_id, accounts, &legs)
            }
            Instruction::BatchTradeCpi { legs } => {
                handle_batch_trade_cpi(program_id, accounts, &legs)
            }
            Instruction::SetMatcherConfig { enabled } => {
                handle_set_matcher_config(program_id, accounts, enabled)
            }
            Instruction::ClosePortfolio => handle_close_portfolio(program_id, accounts),
            Instruction::TopUpInsurance { amount } => {
                handle_top_up_insurance(program_id, accounts, amount)
            }
            Instruction::TopUpInsuranceDomain { domain, amount } => {
                handle_top_up_insurance_domain(program_id, accounts, domain, amount)
            }
            Instruction::CloseSlab => handle_close_slab(program_id, accounts),
            Instruction::ResolveMarket => handle_resolve_market(program_id, accounts),
            Instruction::TopUpBackingBucket {
                domain,
                amount,
                expiry_slot,
            } => handle_top_up_backing_bucket(program_id, accounts, domain, amount, expiry_slot),
            Instruction::WithdrawBackingBucket { domain, amount } => {
                handle_withdraw_backing_bucket(program_id, accounts, domain, amount)
            }
            Instruction::ConvertReleasedPnl { amount } => {
                handle_convert_released_pnl(program_id, accounts, amount)
            }
            Instruction::CloseResolved { fee_rate_per_slot } => {
                handle_close_resolved(program_id, accounts, fee_rate_per_slot)
            }
            Instruction::UpdateAuthority { new_pubkey } => {
                handle_update_authority(program_id, accounts, new_pubkey)
            }
            Instruction::UpdateAssetAuthority {
                asset_index,
                kind,
                new_pubkey,
            } => handle_update_asset_authority(program_id, accounts, asset_index, kind, new_pubkey),
            Instruction::UpdateLiquidationFeePolicy { cranker_share_bps } => {
                handle_update_liquidation_fee_policy(program_id, accounts, cranker_share_bps)
            }
            Instruction::UpdateMaintenanceFeePolicy { cranker_share_bps } => {
                handle_update_maintenance_fee_policy(program_id, accounts, cranker_share_bps)
            }
            Instruction::UpdateBackingFeePolicy {
                domain,
                fee_bps,
                insurance_share_bps,
            } => handle_update_backing_fee_policy(
                program_id,
                accounts,
                domain,
                fee_bps,
                insurance_share_bps,
            ),
            Instruction::UpdateTradeFeePolicy { trade_fee_base_bps } => {
                handle_update_trade_fee_policy(program_id, accounts, trade_fee_base_bps)
            }
            Instruction::UpdateFeeRedirectPolicy { redirect_bps } => {
                handle_update_fee_redirect_policy(program_id, accounts, redirect_bps)
            }
            Instruction::UpdateMarketInitFeePolicy { min_init_fee } => {
                handle_update_market_init_fee_policy(program_id, accounts, min_init_fee)
            }
            Instruction::UpdateInsuranceWithdrawPolicy {
                deposits_only,
                cooldown_slots,
            } => handle_update_insurance_withdraw_policy(
                program_id,
                accounts,
                deposits_only,
                cooldown_slots,
            ),
            Instruction::WithdrawBackingBucketEarnings { domain, amount } => {
                handle_withdraw_backing_bucket_earnings(program_id, accounts, domain, amount)
            }
            Instruction::SyncBackingDomainLedger { domain } => {
                handle_sync_backing_domain_ledger(program_id, accounts, domain)
            }
            Instruction::SyncInsuranceLedger => handle_sync_insurance_ledger(program_id, accounts),
            Instruction::ConfigurePermissionlessResolve {
                stale_slots,
                force_close_delay_slots,
            } => handle_configure_permissionless_resolve(
                program_id,
                accounts,
                stale_slots,
                force_close_delay_slots,
            ),
            Instruction::ResolveStalePermissionless { now_slot } => {
                handle_resolve_stale_permissionless(program_id, accounts, now_slot)
            }
            Instruction::ConfigureHybridOracle {
                asset_index,
                now_slot,
                now_unix_ts,
                oracle_leg_count,
                oracle_leg_flags,
                max_staleness_secs,
                hybrid_soft_stale_slots,
                mark_ewma_halflife_slots,
                mark_min_fee,
                invert,
                unit_scale,
                conf_filter_bps,
                oracle_leg_feeds,
            } => handle_configure_hybrid_oracle(
                program_id,
                accounts,
                asset_index,
                now_slot,
                now_unix_ts,
                oracle_leg_count,
                oracle_leg_flags,
                max_staleness_secs,
                hybrid_soft_stale_slots,
                mark_ewma_halflife_slots,
                mark_min_fee,
                invert,
                unit_scale,
                conf_filter_bps,
                oracle_leg_feeds,
            ),
            Instruction::ConfigureEwmaMark {
                asset_index,
                now_slot,
                initial_mark_e6,
                mark_ewma_halflife_slots,
                mark_min_fee,
            } => handle_configure_ewma_mark(
                program_id,
                accounts,
                asset_index,
                now_slot,
                initial_mark_e6,
                mark_ewma_halflife_slots,
                mark_min_fee,
            ),
            Instruction::PushEwmaMark {
                asset_index,
                now_slot,
                mark_e6,
            } => handle_push_ewma_mark(program_id, accounts, asset_index, now_slot, mark_e6),
            Instruction::ConfigureAuthMark {
                asset_index,
                now_slot,
                initial_mark_e6,
            } => handle_configure_auth_mark(
                program_id,
                accounts,
                asset_index,
                now_slot,
                initial_mark_e6,
            ),
            Instruction::PushAuthMark {
                asset_index,
                now_slot,
                mark_e6,
            } => handle_push_auth_mark(program_id, accounts, asset_index, now_slot, mark_e6),
            Instruction::ForceCloseAbandonedAsset {
                asset_index,
                now_slot,
                close_q,
            } => handle_force_close_abandoned_asset(
                program_id,
                accounts,
                asset_index,
                now_slot,
                close_q,
            ),
            Instruction::RestartAssetOracle {
                asset_index,
                now_slot,
                initial_price,
            } => handle_restart_asset_oracle(
                program_id,
                accounts,
                asset_index,
                now_slot,
                initial_price,
            ),
            Instruction::UpdateAssetLifecycle {
                action,
                asset_index,
                now_slot,
                initial_price,
                insurance_authority,
                insurance_operator,
                backing_bucket_authority,
                oracle_authority,
            } => handle_update_asset_lifecycle(
                program_id,
                accounts,
                action,
                asset_index,
                now_slot,
                initial_price,
                insurance_authority,
                insurance_operator,
                backing_bucket_authority,
                oracle_authority,
            ),
            Instruction::WithdrawInsurance { amount } => {
                handle_withdraw_insurance(program_id, accounts, amount)
            }
            Instruction::WithdrawInsuranceAsset {
                asset_index,
                amount,
            } => handle_withdraw_insurance_asset(program_id, accounts, asset_index, amount),
            Instruction::CureAndCancelClose { optional_deposit } => {
                handle_cure_and_cancel_close(program_id, accounts, optional_deposit)
            }
            Instruction::ForfeitRecoveryLeg {
                asset_index,
                b_delta_budget,
            } => handle_forfeit_recovery_leg(program_id, accounts, asset_index, b_delta_budget),
            Instruction::RebalanceReduce {
                asset_index,
                reduce_q,
            } => handle_rebalance_reduce(program_id, accounts, asset_index, reduce_q),
            Instruction::FinalizeResetSide { asset_index, side } => {
                handle_finalize_reset_side(program_id, accounts, asset_index, side)
            }
            Instruction::ClaimResolvedPayoutTopup => {
                handle_claim_resolved_payout_topup(program_id, accounts)
            }
            Instruction::RefineResolvedUnreceiptedBound { decrease_num } => {
                handle_refine_resolved_unreceipted_bound(program_id, accounts, decrease_num)
            }
            Instruction::SyncMaintenanceFee { now_slot } => {
                handle_sync_maintenance_fee(program_id, accounts, now_slot)
            }
            Instruction::UpdateBaseUnitMints {
                primary_mint,
                secondary_mint,
            } => handle_update_base_unit_mints(program_id, accounts, primary_mint, secondary_mint),
            Instruction::SwapSecondaryForPrimary { amount } => {
                handle_swap_secondary_for_primary(program_id, accounts, amount)
            }
            // ── Fork LP Vault (tags 74-80) ───────────────────────────────────
            Instruction::CreateLpVault {
                fee_share_bps,
                redemption_cooldown_slots,
                oi_reservation_threshold_bps,
                domain,
            } => handle_create_lp_vault(
                program_id,
                accounts,
                fee_share_bps,
                redemption_cooldown_slots,
                oi_reservation_threshold_bps,
                domain,
            ),
            Instruction::DepositToLpVault { amount, domain } => {
                handle_deposit_to_lp_vault(program_id, accounts, amount, domain)
            }
            Instruction::RebalanceLpVaultBacking {
                from_domain,
                to_domain,
                amount,
            } => handle_rebalance_lp_vault_backing(
                program_id, accounts, from_domain, to_domain, amount,
            ),
            Instruction::RequestRedeemLpShares { shares } => {
                handle_request_redeem_lp_shares(program_id, accounts, shares)
            }
            Instruction::ExecuteRedemption { domain } => {
                handle_execute_redemption(program_id, accounts, domain)
            }
            Instruction::LpVaultCrankFees { domain } => {
                handle_lp_vault_crank_fees(program_id, accounts, domain)
            }
            Instruction::SetLpVaultPaused { paused } => {
                handle_set_lp_vault_paused(program_id, accounts, paused)
            }
            Instruction::CloseLpVault => handle_close_lp_vault(program_id, accounts),
            Instruction::CancelRedemption => handle_cancel_redemption(program_id, accounts),
            // ── Fork NFT / B-3 (tags 72/73) ──────────────────────────────────
            Instruction::TransferPortfolioOwnership {
                new_owner,
                asset_index,
            } => handle_transfer_portfolio_ownership(program_id, accounts, new_owner, asset_index),
            Instruction::SetNftProgramId { nft_program_id } => {
                handle_set_nft_program_id(program_id, accounts, nft_program_id)
            }
            Instruction::UnwrapEscrowedPortfolio { new_owner } => {
                handle_unwrap_escrowed_portfolio(program_id, accounts, new_owner)
            }
            Instruction::InitMatcherCtx {
                kind,
                trading_fee_bps,
                base_spread_bps,
                max_total_bps,
                impact_k_bps,
                liquidity_notional_e6,
                max_fill_abs,
                max_inventory_abs,
                fee_to_insurance_bps,
                skew_spread_mult_bps,
            } => handle_init_matcher_ctx(
                program_id,
                accounts,
                kind,
                trading_fee_bps,
                base_spread_bps,
                max_total_bps,
                impact_k_bps,
                liquidity_notional_e6,
                max_fill_abs,
                max_inventory_abs,
                fee_to_insurance_bps,
                skew_spread_mult_bps,
            ),
            Instruction::WithdrawProtocolFee { amount } => {
                handle_withdraw_protocol_fee(program_id, accounts, amount)
            }
            Instruction::SetProtocolFeeAuthority { new_authority } => {
                handle_set_protocol_fee_authority(program_id, accounts, new_authority)
            }
            Instruction::UpdateFeeSplit {
                creator_share_bps,
                lp_share_bps,
                insurance_share_bps,
            } => handle_update_fee_split(
                program_id,
                accounts,
                creator_share_bps,
                lp_share_bps,
                insurance_share_bps,
            ),
            Instruction::WithdrawInsuranceReserveToStake => {
                handle_withdraw_insurance_reserve_to_stake(program_id, accounts)
            }
            Instruction::UpdateMaintenanceFeePerSlot {
                maintenance_fee_per_slot,
            } => handle_update_maintenance_fee_per_slot(
                program_id,
                accounts,
                maintenance_fee_per_slot,
            ),
            Instruction::ExpireBackingBucket { domain } => {
                handle_expire_backing_bucket(program_id, accounts, domain)
            }
            Instruction::WithdrawCreatorFee { amount } => {
                handle_withdraw_creator_fee(program_id, accounts, amount)
            }
        }
    }

    #[inline(never)]
    fn handle_init_market<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        max_portfolio_assets: u16,
        h_min: u64,
        h_max: u64,
        initial_price: u64,
        min_nonzero_mm_req: u128,
        min_nonzero_im_req: u128,
        maintenance_margin_bps: u64,
        initial_margin_bps: u64,
        max_trading_fee_bps: u64,
        trade_fee_base_bps: u64,
        liquidation_fee_bps: u64,
        liquidation_fee_cap: u128,
        min_liquidation_abs: u128,
        max_price_move_bps_per_slot: u64,
        max_accrual_dt_slots: u64,
        max_abs_funding_e9_per_slot: u64,
        min_funding_lifetime_slots: u64,
        max_account_b_settlement_chunks: u64,
        max_bankrupt_close_chunks: u64,
        max_bankrupt_close_lifetime_slots: u64,
        public_b_chunk_atoms: u128,
        maintenance_fee_per_slot: u128,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let mint_ai = account(accounts, 2)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        verify_mint(mint_ai)?;
        if trade_fee_base_bps > max_trading_fee_bps
            || max_portfolio_assets == 0
            || max_portfolio_assets > constants::WRAPPER_MAX_PORTFOLIO_ASSETS
            || h_max as u128 > BOUND_SCALE
            || maintenance_fee_per_slot > percolator::MAX_PROTOCOL_FEE_ABS
        {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let mut cfg = V16Config::public_user_fund(max_portfolio_assets, h_min, h_max);
        cfg.min_nonzero_mm_req = min_nonzero_mm_req;
        cfg.min_nonzero_im_req = min_nonzero_im_req;
        cfg.maintenance_margin_bps = maintenance_margin_bps;
        cfg.initial_margin_bps = initial_margin_bps;
        cfg.max_trading_fee_bps = max_trading_fee_bps;
        cfg.liquidation_fee_bps = liquidation_fee_bps;
        cfg.liquidation_fee_cap = liquidation_fee_cap;
        cfg.min_liquidation_abs = min_liquidation_abs;
        cfg.max_price_move_bps_per_slot = max_price_move_bps_per_slot;
        cfg.max_accrual_dt_slots = max_accrual_dt_slots;
        cfg.max_abs_funding_e9_per_slot = max_abs_funding_e9_per_slot;
        cfg.min_funding_lifetime_slots = min_funding_lifetime_slots;
        cfg.max_account_b_settlement_chunks = max_account_b_settlement_chunks;
        cfg.max_bankrupt_close_chunks = max_bankrupt_close_chunks;
        cfg.max_bankrupt_close_lifetime_slots = max_bankrupt_close_lifetime_slots;
        cfg.public_b_chunk_atoms = public_b_chunk_atoms;
        if initial_price == 0 || initial_price > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        // WARNING (not a repair): say so loudly when this market's funding
        // cannot accrue at its genesis price. See `warn_if_funding_cannot_accrue`
        // for why this warns rather than rejects. The flooring itself lives in
        // the engine and is NOT changed.
        warn_if_funding_cannot_accrue(
            max_abs_funding_e9_per_slot,
            max_accrual_dt_slots,
            initial_price,
        );
        let init_slot = Clock::get().map(|c| c.slot).unwrap_or(0);
        let wrapper = WrapperConfigV16 {
            marketauth: admin.key.to_bytes(),
            collateral_mint: mint_ai.key.to_bytes(),
            secondary_collateral_mint: [0u8; 32],
            maintenance_fee_per_slot,
            permissionless_market_init_fee: 0,
            // No fee-split floor check applies here, and none is needed:
            // InitMarket hardcodes the DEFAULT shares (1600/4800/1600), which
            // sum to FEE_SHARE_TOTAL_BPS and clear every floor by construction.
            // A market that never calls a setter is already compliant.
            //
            // CORRECTED: this used to say the floor "is enforced once
            // backing/insurance shares are actually configured, via the two
            // setters", pointing at `policy_v16::fee_split_floor_ok`. Both
            // setters dropped that check and `fee_split_floor_ok` is retired.
            // The only floor enforcement point is `handle_update_fee_split`
            // (tag 86) via `policy_v16::validate_fee_split`.
            trade_fee_base_bps,
            permissionless_resolve_stale_slots: 0,
            force_close_delay_slots: 0,
            last_good_oracle_slot: init_slot,
            insurance_withdraw_deposit_remaining: 0,
            insurance_withdraw_max_bps: 0,
            liquidation_cranker_fee_share_bps: 0,
            maintenance_cranker_fee_share_bps: 0,
            backing_trade_fee_bps_long: 0,
            backing_trade_fee_bps_short: 0,
            unit_scale: 0,
            conf_filter_bps: 0,
            insurance_withdraw_deposits_only: 0,
            oracle_mode: constants::ORACLE_MODE_MANUAL,
            oracle_leg_count: 0,
            oracle_leg_flags: 0,
            invert: 0,
            _padding0: 0,
            free_market_slot_count: 0,
            insurance_withdraw_cooldown_slots: 0,
            last_insurance_withdraw_slot: 0,
            max_staleness_secs: 0,
            hybrid_soft_stale_slots: 0,
            mark_ewma_e6: initial_price,
            mark_ewma_last_slot: init_slot,
            mark_ewma_halflife_slots: constants::DEFAULT_MARK_EWMA_HALFLIFE_SLOTS,
            mark_min_fee: 0,
            oracle_target_price_e6: initial_price,
            oracle_target_publish_time: 0,
            oracle_leg_feeds: [[0u8; 32]; constants::ORACLE_LEG_CAP],
            oracle_leg_prices_e6: [0u64; constants::ORACLE_LEG_CAP],
            oracle_leg_publish_times: [0i64; constants::ORACLE_LEG_CAP],
            backing_trade_fee_policy_count: 0,
            backing_trade_fee_insurance_share_bps_long: 0,
            backing_trade_fee_insurance_share_bps_short: 0,
            fee_redirect_to_market_0_bps: 0,
            // Protocol-fee program change: unconditionally set to the
            // hardcoded default at construction, never a caller-supplied
            // argument -- no code path can create a market with a
            // zero/attacker-controlled protocol_fee_authority.
            protocol_fee_authority: constants::PROTOCOL_FEE_AUTHORITY_DEFAULT.to_bytes(),
            protocol_fee_accrued_atoms: 0,
            protocol_fee_withdrawn_atoms: 0,
            // Fee-split: hardcoded defaults, never caller-supplied, so no market
            // can be created with a zero or hostile split. A market that never
            // calls UpdateFeeSplit still pays all four legs correctly.
            lp_fee_accrued_atoms: 0,
            lp_fee_withdrawn_atoms: 0,
            insurance_reserve_accrued_atoms: 0,
            insurance_reserve_withdrawn_atoms: 0,
            creator_share_bps: constants::DEFAULT_CREATOR_SHARE_BPS,
            lp_share_bps: constants::DEFAULT_LP_SHARE_BPS,
            insurance_share_bps: constants::DEFAULT_INSURANCE_SHARE_BPS,
            _padding_split: [0u8; 2],
            // Creator fee claim: a brand-new market has earned nothing yet.
            creator_fee_claimable_atoms: 0,
        };
        state::init_market_account_zero_copy(
            &mut market_ai.try_borrow_mut_data()?,
            &wrapper,
            cfg,
            market_ai.key.to_bytes(),
            initial_price,
            init_slot,
        )
    }

    #[inline(never)]
    fn handle_init_portfolio<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_signer(owner)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        if state::is_initialized(&portfolio_ai.try_borrow_data()?) {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        let (cfg, mode, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let source_domain_count =
            v16_domain_count_for_market_slots(max_market_slots as u32).map_err(map_v16_error)?;
        let required_portfolio_len =
            state::portfolio_account_len_for_market_slots(max_market_slots)?;
        if portfolio_ai.data_len() < required_portfolio_len {
            portfolio_ai.realloc(required_portfolio_len, true)?;
        }
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            let last_fee_slot = authenticated_market_slot_or_fallback_view(&group);
            state::init_portfolio_account_zero_copy(
                &mut portfolio_ai.try_borrow_mut_data()?,
                market_ai.key.to_bytes(),
                portfolio_ai.key.to_bytes(),
                owner.key.to_bytes(),
                last_fee_slot,
                max_market_slots,
            )?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            portfolio
                .as_view()
                .validate_with_market(&group.as_view())
                .map_err(map_v16_error)?;
            group
                .register_empty_materialized_portfolio_not_atomic(&portfolio.as_view())
                .map_err(map_v16_error)?;
        }
        let _ = (cfg, source_domain_count);
        Ok(())
    }

    #[inline(never)]
    fn handle_deposit<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        let source_token = account(accounts, 3)?;
        let vault_token = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        expect_signer(owner)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_writable(source_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        verify_token_program(token_program)?;

        let (cfg, mode, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let mint = primary_collateral_mint(&cfg);
        let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
        verify_user_token_account(source_token, owner.key, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(source_token, amount_u64)?;

        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            // E2: owner==signer OR the signer holds the bound NFT (escrowed position).
            // Optional trailing accounts [6]=nft_registry [7]=PositionNft PDA [8]=signer NFT ATA.
            // Lets an NFT holder margin-defend a wrapped position (#146).
            let nft = optional_nft_holder_accounts(accounts, 6);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
            group
                .deposit_not_atomic(&mut portfolio, amount)
                .map_err(map_v16_error)?;
        }
        transfer_tokens(token_program, source_token, vault_token, owner, amount_u64)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_withdraw<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        let dest_token = account(accounts, 3)?;
        let vault_token = account(accounts, 4)?;
        let vault_authority_ai = account(accounts, 5)?;
        let token_program = account(accounts, 6)?;
        expect_signer(owner)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        verify_token_program(token_program)?;

        let (cfg, mode, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        verify_withdrawable_token_accounts(
            dest_token,
            owner.key,
            vault_token,
            &vault_authority,
            &cfg,
        )?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(vault_token, amount_u64)?;

        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            // E2: owner==signer OR signer holds the bound NFT. Optional trailing
            // accounts [7]=nft_registry [8]=PositionNft PDA [9]=signer NFT ATA.
            // FUND-SAFETY: the dest-token check uses `owner.key` (the SIGNER), so an
            // NFT-holder withdrawal pays the HOLDER, never the escrow PDA.
            let nft = optional_nft_holder_accounts(accounts, 7);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
            group
                .withdraw_not_atomic(&mut portfolio, amount)
                .map_err(map_v16_error)?;
        }
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )
    }

    #[inline(never)]
    fn handle_trade_nocpi_zero_copy<'a>(
        _program_id: &Pubkey,
        account_a_owner_key: &Pubkey,
        account_b_owner_key: &Pubkey,
        market_ai: &AccountInfo<'a>,
        account_a_ai: &AccountInfo<'a>,
        account_b_ai: &AccountInfo<'a>,
        asset_index: u16,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
        max_market_slots: usize,
    ) -> ProgramResult {
        ensure_portfolio_storage_for_market_slots(account_a_ai, max_market_slots)?;
        ensure_portfolio_storage_for_market_slots(account_b_ai, max_market_slots)?;
        let mut cfg_after = None;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let mut oracle_profile =
                read_oracle_profile_from_view(&group, &cfg, asset_index as usize)?;
            reject_permissionless_resolve_matured_live_for_profile_view(
                &cfg,
                &oracle_profile,
                &group,
            )?;
            let mut account_a_data = account_a_ai.try_borrow_mut_data()?;
            let mut account_b_data = account_b_ai.try_borrow_mut_data()?;
            let mut account_a =
                state::portfolio_view_mut_for_market_slots(&mut account_a_data, max_market_slots)?;
            let mut account_b =
                state::portfolio_view_mut_for_market_slots(&mut account_b_data, max_market_slots)?;
            expect_portfolio_view_account_key(&account_a, account_a_ai.key)?;
            expect_portfolio_view_account_key(&account_b, account_b_ai.key)?;
            expect_portfolio_view_owner(&account_a, account_a_owner_key)?;
            expect_portfolio_view_owner(&account_b, account_b_owner_key)?;
            let size_abs = if size_q == i128::MIN || size_q == 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            } else {
                size_q.unsigned_abs()
            };
            // F-TRADENOCPI-FEE: the position enters/settles at the asset mark (effective_price), NOT at
            // the caller-supplied exec_price. The engine uses request.exec_price ONLY as the fee notional
            // basis (fee = size_q*exec_price/POS_SCALE * fee_bps), so without pinning it two cooperating
            // accounts could declare a tiny exec_price to pay an arbitrarily small fee on a full
            // mark-valued trade. Bill the fee on the mark (the price the trade actually settles at),
            // mirroring TradeCpi where the matcher's exec_price_e6 must equal the oracle price.
            // NOTE: the ORIGINAL caller exec_price is still passed to update_hybrid_mark_after_trade_view
            // below — in hybrid mode that is the reported trade price that drives mark discovery (bounded
            // by the EWMA/clamp), a distinct role from the fee basis.
            let fee_basis_price = group.markets[asset_index as usize]
                .engine
                .asset
                .effective_price
                .get();
            let fee_bps = hybrid_trade_fee_bps_view(
                &cfg,
                &oracle_profile,
                &group,
                asset_index as usize,
                size_abs,
                fee_basis_price,
                fee_bps,
            )?;
            let req = TradeRequestV16 {
                asset_index: asset_index as usize,
                // size_q is signed (i128) in the engine; direction is carried by the long/short
                // account orientation chosen below (size_q > 0 ? (a,b) : (b,a)), so pass the
                // positive magnitude here to preserve the existing single-trade semantics.
                size_q: size_abs as i128,
                exec_price: fee_basis_price,
                fee_bps,
            };
            ensure_trade_portfolios_current_for_requests_view(
                &group,
                &account_a,
                &account_b,
                core::slice::from_ref(&req),
            )?;
            let backing_before = if cfg.backing_trade_fee_policy_count == 0 {
                None
            } else {
                Some((
                    source_counterparty_backing_snapshot_view(&account_a)?,
                    source_counterparty_backing_snapshot_view(&account_b)?,
                ))
            };
            let source_lien_before_a =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_a)?;
            let source_lien_before_b =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_b)?;
            // Taker-only (design §1A): account_a is always the taker/fee-payer
            // (§1A.2). Whether account_a occupies the engine's first
            // (long_account) or second (short_account) positional slot
            // depends on the sign of the caller-supplied size_q, since this
            // single-trade path reorders (a,b) by sign (§1A.3) -- so
            // `taker_is_long_account` must mirror that same reordering.
            let outcome = if size_q > 0 {
                group
                    .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                        &mut account_a,
                        &mut account_b,
                        req,
                        true, // account_a (taker) is long_account here
                    )
                    .map_err(map_v16_error)?
            } else {
                group
                    .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                        &mut account_b,
                        &mut account_a,
                        req,
                        false, // account_a (taker) is short_account here
                    )
                    .map_err(map_v16_error)?
            };
            let backing_domain_fee =
                if let Some((backing_before_a, backing_before_b)) = backing_before {
                    apply_backing_domain_fees_after_trade_view(
                        &cfg,
                        &mut group,
                        &mut account_a,
                        backing_before_a.as_ref(),
                        &mut account_b,
                        backing_before_b.as_ref(),
                    )?
                } else {
                    0
                };
            // Four-way split (2026-07-19 design). Taker-only (§1A) guarantees
            // exactly one of outcome.fee_a/fee_b is nonzero, so splitting 0 is
            // all-zeros and the maker's domain gets exactly the 0 credit it
            // should -- no special-casing needed.
            let split_a = policy_v16::split_trade_fee(
                outcome.fee_a,
                constants::PROTOCOL_FEE_BPS,
                cfg.creator_share_bps,
                cfg.lp_share_bps,
                cfg.insurance_share_bps,
            )?;
            let split_b = policy_v16::split_trade_fee(
                outcome.fee_b,
                constants::PROTOCOL_FEE_BPS,
                cfg.creator_share_bps,
                cfg.lp_share_bps,
                cfg.insurance_share_bps,
            )?;
            // Creator-fee-claim change (2026-07-23): the creator leg NO LONGER
            // goes to the domain insurance budget. That budget is the loss
            // backstop the engine draws down via
            // `consume_domain_insurance_for_negative_pnl`, and its only exit
            // (tag 57 `WithdrawInsuranceAsset`) let a creator drain the
            // backstop while the market was healthy. The leg now accrues to a
            // dedicated counter claimable only via tag 90.
            let creator_cut_total = split_a
                .creator
                .checked_add(split_b.creator)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;

            let protocol_cut_total = split_a
                .protocol
                .checked_add(split_b.protocol)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            let lp_cut_total = split_a
                .lp
                .checked_add(split_b.lp)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            let insurance_cut_total = split_a
                .insurance
                .checked_add(split_b.insurance)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;

            if protocol_cut_total != 0
                || lp_cut_total != 0
                || insurance_cut_total != 0
                || creator_cut_total != 0
            {
                cfg.protocol_fee_accrued_atoms = cfg
                    .protocol_fee_accrued_atoms
                    .checked_add(protocol_cut_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                cfg.lp_fee_accrued_atoms = cfg
                    .lp_fee_accrued_atoms
                    .checked_add(lp_cut_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                cfg.insurance_reserve_accrued_atoms = cfg
                    .insurance_reserve_accrued_atoms
                    .checked_add(insurance_cut_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                // u128 -> u64 narrowing: the counter is u64 because it had to
                // fit the 8 spare bytes of `_padding_split`. Overflow (either
                // the narrowing or the add) ERRORS the whole trade rather than
                // wrapping or saturating.
                cfg.creator_fee_claimable_atoms = cfg
                    .creator_fee_claimable_atoms
                    .checked_add(
                        u64::try_from(creator_cut_total)
                            .map_err(|_| PercolatorError::EngineArithmeticOverflow)?,
                    )
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                // CRITICAL: force the write-back below even if nothing else in
                // this instruction would otherwise have dirtied cfg. The cfg_after
                // pattern is opt-in per mutation -- a missed write-back here
                // SILENTLY DISCARDS accrued fees for all four legs.
                cfg_after = Some(cfg);
            }
            update_hybrid_mark_after_trade_view(
                &mut oracle_profile,
                &group,
                asset_index as usize,
                exec_price,
                outcome
                    .fee_a
                    .checked_add(outcome.fee_b)
                    .and_then(|v| v.checked_add(backing_domain_fee))
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?,
            )?;
            write_oracle_profile_to_view(&mut group, asset_index as usize, &oracle_profile)?;
            if asset_index == 0 && oracle_v16::profile_is_price_managed(&oracle_profile) {
                cfg.mark_ewma_e6 = oracle_profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = oracle_profile.mark_ewma_last_slot;
                cfg_after = Some(cfg);
            }
            group.validate_shape().map_err(map_v16_error)?;
            let source_lien_after_a =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_a)?;
            let source_lien_after_b =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_b)?;
            ensure_new_source_lien_domains_full_rate_for_trade_view(
                &group,
                source_lien_before_a.as_ref(),
                source_lien_after_a.as_ref(),
                source_lien_before_b.as_ref(),
                source_lien_after_b.as_ref(),
            )?;
        }
        if let Some(cfg) = cfg_after {
            state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)?;
        }
        Ok(())
    }

    /// Reconstruct the exact per-leg fee the engine charges for one leg, so wrapper-side
    /// per-asset/per-domain fee accounting can be split out of the engine's AGGREGATE batch
    /// outcome. FIX E4 (upstream engine 8f25aa5d, "charge sub-atom trade fees on ceil
    /// notional"): the engine now computes the fee on `trade_fee_notional_ceil` (ceil), NOT the
    /// `trade_notional_floor` (floor) used for margin/PnL bookkeeping -- a sub-atom fill
    /// (abs_size_q * exec_price / POS_SCALE < 1) floors to notional=0 (and therefore fee=0) even
    /// though it opens nonzero OI. Mirrors that: `fee_notional` here is the ceil (matching engine
    /// `risk_notional_ceil` / `trade_fee_notional_ceil`), then `checked_fee_bps`-equivalent ceil
    /// division on top for the fee itself. Extreme sizes that would need the engine's U256
    /// widening error out (the batch then rejects rather than mis-accounting — see the aggregate
    /// cross-check below). Before this fix, batch_leg_fee still used floor notional post-E4,
    /// so any NoCpi batch containing a sub-atom-notional leg would reconstruct fee=0 for that
    /// leg while the engine's aggregate outcome.fee_a/fee_b included its ceil-rounded fee atom,
    /// tripping the `reconstructed_total != engine_total` guard and hard-reverting the whole
    /// batch (fails closed, but an availability gap for otherwise-legitimate batches).
    pub fn batch_leg_fee(
        abs_size_q: u128,
        exec_price: u64,
        fee_bps: u64,
    ) -> Result<u128, ProgramError> {
        if abs_size_q == 0 || fee_bps == 0 {
            return Ok(0);
        }
        let product = abs_size_q
            .checked_mul(exec_price as u128)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let pos_scale = percolator::POS_SCALE;
        let fee_notional = (product / pos_scale) + u128::from(product % pos_scale != 0);
        if fee_notional == 0 {
            return Ok(0);
        }
        let product = fee_notional
            .checked_mul(fee_bps as u128)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let den = percolator::MAX_MARGIN_BPS as u128;
        Ok((product / den) + u128::from(product % den != 0))
    }

    /// Atomic multi-leg batch trade. `account_a` (taker) is the long side, `account_b` (LP) the
    /// short side; each leg's SIGNED `size_q` decides that leg's direction, so one batch can carry
    /// a mixed long/short spread. The engine settles both accounts ONCE, applies every leg, then
    /// runs a SINGLE end-state initial-margin check — interim legs need not be individually
    /// margin-feasible. The wrapper still does its per-asset bookkeeping (fee basis, per-domain fee
    /// crediting, hybrid-mark discovery, oracle-profile writeback) for each leg around that one
    /// engine call.
    #[inline(never)]
    fn handle_batch_trade_nocpi<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        legs: &[ix::BatchTradeLeg],
    ) -> ProgramResult {
        let signer_a = account(accounts, 0)?;
        let signer_b = account(accounts, 1)?;
        let market_ai = account(accounts, 2)?;
        let account_a_ai = account(accounts, 3)?;
        let account_b_ai = account(accounts, 4)?;
        expect_signer(signer_a)?;
        expect_signer(signer_b)?;
        expect_writable(market_ai)?;
        expect_writable(account_a_ai)?;
        expect_writable(account_b_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(account_a_ai, program_id)?;
        expect_owner(account_b_ai, program_id)?;
        if account_a_ai.key == account_b_ai.key {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (_cfg_pre, mode_pre, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        handle_batch_execute_zero_copy(
            program_id,
            signer_a.key,
            signer_b.key,
            market_ai,
            account_a_ai,
            account_b_ai,
            legs,
            max_market_slots,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_batch_execute_zero_copy<'a>(
        _program_id: &Pubkey,
        account_a_owner_key: &Pubkey,
        account_b_owner_key: &Pubkey,
        market_ai: &AccountInfo<'a>,
        account_a_ai: &AccountInfo<'a>,
        account_b_ai: &AccountInfo<'a>,
        legs: &[ix::BatchTradeLeg],
        max_market_slots: usize,
    ) -> ProgramResult {
        if legs.is_empty() {
            return Err(PercolatorError::EngineNonProgress.into());
        }
        ensure_portfolio_storage_for_market_slots(account_a_ai, max_market_slots)?;
        ensure_portfolio_storage_for_market_slots(account_b_ai, max_market_slots)?;
        let mut cfg_after = None;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            // v1 scope: per-leg backing-domain trade fees are not split in a batch yet. If a backing
            // fee policy is configured, reject so we never silently skip those fees.
            if cfg.backing_trade_fee_policy_count != 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let mut account_a_data = account_a_ai.try_borrow_mut_data()?;
            let mut account_b_data = account_b_ai.try_borrow_mut_data()?;
            let mut account_a =
                state::portfolio_view_mut_for_market_slots(&mut account_a_data, max_market_slots)?;
            let mut account_b =
                state::portfolio_view_mut_for_market_slots(&mut account_b_data, max_market_slots)?;
            expect_portfolio_view_account_key(&account_a, account_a_ai.key)?;
            expect_portfolio_view_account_key(&account_b, account_b_ai.key)?;
            expect_portfolio_view_owner(&account_a, account_a_owner_key)?;
            expect_portfolio_view_owner(&account_b, account_b_owner_key)?;

            // Pre-pass: per leg, read its oracle profile, pin the fee basis to the asset mark, and
            // build the SIGNED engine request. Reject duplicate assets (one leg per asset per batch).
            let mut requests: Vec<TradeRequestV16> = Vec::with_capacity(legs.len());
            // (asset_index, oracle_profile, reported_exec_price, fee_basis_price, fee_bps_eff,
            // abs_size).
            //
            // A 7th element, `leg_size_q` (the raw signed per-leg size), used to
            // be carried through so the taker-only post-pass could pick the
            // correct single DOMAIN per leg (§1A.3) for the creator-leg budget
            // credit. The creator-fee-claim change (2026-07-23) routes that leg
            // to `cfg.creator_fee_claimable_atoms` instead of a domain budget,
            // so no per-leg domain is selected any more and the field is gone.
            let mut leg_ctx: Vec<(usize, state::AssetOracleProfileV16, u64, u64, u64, u128)> =
                Vec::with_capacity(legs.len());
            for leg in legs {
                let asset_index = leg.asset_index as usize;
                if requests.iter().any(|r| r.asset_index == asset_index) {
                    return Err(PercolatorError::InvalidInstruction.into());
                }
                let oracle_profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;
                reject_permissionless_resolve_matured_live_for_profile_view(
                    &cfg,
                    &oracle_profile,
                    &group,
                )?;
                if leg.size_q == i128::MIN || leg.size_q == 0 {
                    return Err(PercolatorError::InvalidInstruction.into());
                }
                let abs_size = leg.size_q.unsigned_abs();
                let fee_basis_price = group.markets[asset_index]
                    .engine
                    .asset
                    .effective_price
                    .get();
                let fee_bps_eff = hybrid_trade_fee_bps_view(
                    &cfg,
                    &oracle_profile,
                    &group,
                    asset_index,
                    abs_size,
                    fee_basis_price,
                    leg.fee_bps,
                )?;
                requests.push(TradeRequestV16 {
                    asset_index,
                    size_q: leg.size_q,
                    exec_price: fee_basis_price,
                    fee_bps: fee_bps_eff,
                });
                leg_ctx.push((
                    asset_index,
                    oracle_profile,
                    leg.exec_price,
                    fee_basis_price,
                    fee_bps_eff,
                    abs_size,
                ));
            }
            ensure_trade_portfolios_current_for_requests_view(
                &group, &account_a, &account_b, &requests,
            )?;

            let source_lien_before_a =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_a)?;
            let source_lien_before_b =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_b)?;

            // Taker-only (design §1A.3): batches never reorder -- account_a is
            // always the engine's first (long_account) positional slot for
            // the whole call, and account_a is always the taker (§1A.2).
            let outcome = group
                .execute_batch_with_fee_loss_stale_scoped_not_atomic(
                    &mut account_a,
                    &mut account_b,
                    &requests,
                    true,
                )
                .map_err(map_v16_error)?;

            // Taker-only + N1 (design §1A.3/§1A.4): within one batch call,
            // exactly one physical account pays across the WHOLE batch --
            // pnl (the only thing `charge_account_fee_current_not_atomic`'s
            // waiver reads) is invariant across legs within a single call
            // (only capital changes as fees are charged; nothing in the
            // per-leg loop -- position-delta application, residual-reward
            // transfer, recertification -- touches pnl), so it is never a
            // per-leg mix. `outcome.fee_a`/`outcome.fee_b` are the engine's
            // AGGREGATE totals across all legs; whichever is nonzero
            // identifies the uniform payer for this whole batch.
            let taker_paid = outcome.fee_a > 0;
            let maker_paid = outcome.fee_b > 0;
            if taker_paid && maker_paid {
                // Unreachable given the engine's taker-only charge shape
                // (see proof_v16_taker_only_charges_exactly_one_side in
                // percolator/tests/proofs_v16.rs), but the wrapper does not
                // trust that invariant blindly across the ABI boundary.
                return Err(PercolatorError::EngineArithmeticOverflow.into());
            }

            // Post-pass: accrue each leg's four-way fee split into the four config counters and
            // drive each asset's hybrid mark. Fees are reconstructed deterministically per leg;
            // the running total must equal the engine's aggregate or we refuse the batch (no
            // silent mis-accounting). Symmetric with the single-trade credit site above.
            //
            // Creator-fee-claim change (2026-07-23): the creator leg no longer lands in a domain
            // insurance budget here either -- it accrues into
            // `cfg.creator_fee_claimable_atoms` via `creator_cut_running_total`, exactly like the
            // other three legs' running totals, and is folded in once after the loop.
            let mut reconstructed_total: u128 = 0;
            let mut cfg_dirty = false;
            let mut protocol_cut_running_total: u128 = 0;
            let mut lp_cut_running_total: u128 = 0;
            let mut insurance_cut_running_total: u128 = 0;
            let mut creator_cut_running_total: u128 = 0;
            for (
                asset_index,
                oracle_profile,
                reported_price,
                fee_basis_price,
                fee_bps_eff,
                abs_size,
            ) in leg_ctx.iter_mut()
            {
                let fee_leg = batch_leg_fee(*abs_size, *fee_basis_price, *fee_bps_eff)?;
                if fee_leg != 0 {
                    let split_leg = policy_v16::split_trade_fee(
                        fee_leg,
                        constants::PROTOCOL_FEE_BPS,
                        cfg.creator_share_bps,
                        cfg.lp_share_bps,
                        cfg.insurance_share_bps,
                    )?;
                    protocol_cut_running_total = protocol_cut_running_total
                        .checked_add(split_leg.protocol)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                    lp_cut_running_total = lp_cut_running_total
                        .checked_add(split_leg.lp)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                    insurance_cut_running_total = insurance_cut_running_total
                        .checked_add(split_leg.insurance)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                    creator_cut_running_total = creator_cut_running_total
                        .checked_add(split_leg.creator)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                    // NOTE (behaviour preserved): the creator leg used to be
                    // credited only under `if taker_paid { .. } else if
                    // maker_paid { .. }`, i.e. dropped when NEITHER side paid.
                    // Accruing it unconditionally (as the other three legs
                    // already did) is equivalent: if neither side paid,
                    // `engine_total` is 0 while `reconstructed_total` is
                    // nonzero, so the post-loop cross-check below hard-rejects
                    // the whole batch and no counter is ever written back.
                }
                reconstructed_total = reconstructed_total
                    .checked_add(fee_leg)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                update_hybrid_mark_after_trade_view(
                    oracle_profile,
                    &group,
                    *asset_index,
                    *reported_price,
                    fee_leg,
                )?;
                write_oracle_profile_to_view(&mut group, *asset_index, oracle_profile)?;
                if *asset_index == 0 && oracle_v16::profile_is_price_managed(oracle_profile) {
                    cfg.mark_ewma_e6 = oracle_profile.mark_ewma_e6;
                    cfg.mark_ewma_last_slot = oracle_profile.mark_ewma_last_slot;
                    cfg_dirty = true;
                }
            }
            let engine_total = outcome
                .fee_a
                .checked_add(outcome.fee_b)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            if reconstructed_total != engine_total {
                return Err(PercolatorError::EngineArithmeticOverflow.into());
            }
            if protocol_cut_running_total != 0
                || lp_cut_running_total != 0
                || insurance_cut_running_total != 0
                || creator_cut_running_total != 0
            {
                cfg.protocol_fee_accrued_atoms = cfg
                    .protocol_fee_accrued_atoms
                    .checked_add(protocol_cut_running_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                cfg.lp_fee_accrued_atoms = cfg
                    .lp_fee_accrued_atoms
                    .checked_add(lp_cut_running_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                cfg.insurance_reserve_accrued_atoms = cfg
                    .insurance_reserve_accrued_atoms
                    .checked_add(insurance_cut_running_total)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                // u128 -> u64 narrowing, same as the single-trade site: the
                // counter is u64 because it had to fit the spare 8 bytes of
                // `_padding_split`. Overflow ERRORS the whole batch rather
                // than wrapping or saturating.
                cfg.creator_fee_claimable_atoms = cfg
                    .creator_fee_claimable_atoms
                    .checked_add(
                        u64::try_from(creator_cut_running_total)
                            .map_err(|_| PercolatorError::EngineArithmeticOverflow)?,
                    )
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                // CRITICAL: same write-back-forcing requirement as the
                // single-trade site -- a missed write-back here would
                // silently discard accrued fees for all four legs.
                cfg_dirty = true;
            }
            if cfg_dirty {
                cfg_after = Some(cfg);
            }

            group.validate_shape().map_err(map_v16_error)?;

            let source_lien_after_a =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_a)?;
            let source_lien_after_b =
                source_lien_effective_reserved_snapshot_for_trade_view(&account_b)?;
            ensure_new_source_lien_domains_full_rate_for_trade_view(
                &group,
                source_lien_before_a.as_ref(),
                source_lien_after_a.as_ref(),
                source_lien_before_b.as_ref(),
                source_lien_after_b.as_ref(),
            )?;
        }
        if let Some(cfg) = cfg_after {
            state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn handle_trade_nocpi<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> ProgramResult {
        let signer_a = account(accounts, 0)?;
        let signer_b = account(accounts, 1)?;
        let market_ai = account(accounts, 2)?;
        let account_a_ai = account(accounts, 3)?;
        let account_b_ai = account(accounts, 4)?;
        expect_signer(signer_a)?;
        expect_signer(signer_b)?;
        expect_writable(market_ai)?;
        expect_writable(account_a_ai)?;
        expect_writable(account_b_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(account_a_ai, program_id)?;
        expect_owner(account_b_ai, program_id)?;
        if account_a_ai.key == account_b_ai.key {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (_cfg_pre, mode_pre, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        handle_trade_nocpi_zero_copy(
            program_id,
            signer_a.key,
            signer_b.key,
            market_ai,
            account_a_ai,
            account_b_ai,
            asset_index,
            size_q,
            exec_price,
            fee_bps,
            max_market_slots,
        )
    }

    fn active_leg_for_asset_view(
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        asset_index: usize,
    ) -> Result<percolator::PortfolioLegV16, ProgramError> {
        let mut found = None;
        let mut slot = 0usize;
        while slot < portfolio.header.legs.len() {
            let leg = portfolio.header.legs[slot]
                .try_to_runtime()
                .map_err(map_v16_error)?;
            if leg.active && leg.asset_index as usize == asset_index {
                if found.replace(leg).is_some() {
                    return Err(PercolatorError::EngineHiddenLeg.into());
                }
            }
            slot += 1;
        }
        found.ok_or(PercolatorError::EngineInvalidLeg.into())
    }

    fn source_credit_has_live_amounts(source: SourceCreditStateV16) -> bool {
        source.positive_claim_bound_num != 0
            || source.exact_positive_claim_num != 0
            || source.fresh_reserved_backing_num != 0
            || source.spent_backing_num != 0
            || source.provider_receivable_num != 0
            || source.valid_liened_backing_num != 0
            || source.impaired_liened_backing_num != 0
            || source.insurance_credit_reserved_num != 0
            || source.valid_liened_insurance_num != 0
            || source.impaired_liened_insurance_num != 0
    }

    fn ensure_source_credit_full_rate_for_domain_view(
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> ProgramResult {
        let max_market_slots = group.header.config.max_market_slots.get() as usize;
        let asset_index = domain / 2;
        if max_market_slots > group.markets.len() || asset_index >= max_market_slots {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let slot = &group.markets[asset_index].engine;
        let source = if domain % 2 == 0 {
            slot.source_credit_long
                .try_to_runtime()
                .map_err(map_v16_error)?
        } else {
            slot.source_credit_short
                .try_to_runtime()
                .map_err(map_v16_error)?
        };
        if source_credit_has_live_amounts(source)
            && source.credit_rate_num != percolator::CREDIT_RATE_SCALE
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        Ok(())
    }

    fn ensure_new_source_lien_domains_full_rate_for_trade_view(
        group: &state::MarketViewMutV16<'_>,
        before_a: &[(u32, u128)],
        after_a: &[(u32, u128)],
        before_b: &[(u32, u128)],
        after_b: &[(u32, u128)],
    ) -> ProgramResult {
        // For each account, any domain whose source-lien effective reserve INCREASED across the trade
        // must have its source credit at full rate. After-state is the sparse occupied set (<= CAP);
        // look up the before value by domain (default 0 for a freshly-occupied domain).
        for (after, before) in [(after_a, before_a), (after_b, before_b)] {
            let mut i = 0usize;
            while i < after.len() {
                let (domain, after_val) = after[i];
                if after_val > sparse_domain_value_lookup(before, domain) {
                    ensure_source_credit_full_rate_for_domain_view(group, domain as usize)?;
                }
                i += 1;
            }
        }
        Ok(())
    }

    // Sparse before/after trade snapshots: one (domain, value) entry per OCCUPIED source-domain slot
    // (<= PORTFOLIO_SOURCE_DOMAIN_CAP), so the trade path is O(active source-domains), not O(N).
    fn sparse_domain_value_lookup(snapshot: &[(u32, u128)], domain: u32) -> u128 {
        let mut i = 0usize;
        while i < snapshot.len() {
            if snapshot[i].0 == domain {
                return snapshot[i].1;
            }
            i += 1;
        }
        0
    }

    fn source_lien_effective_reserved_snapshot_for_trade_view(
        account: &percolator::PortfolioV16ViewMut<'_>,
    ) -> Result<alloc::boxed::Box<[(u32, u128)]>, ProgramError> {
        let mut out = Vec::new();
        for slot in account.header.source_domains.iter() {
            if slot.is_occupied() {
                out.push((slot.domain.get(), slot.source_lien_effective_reserved.get()));
            }
        }
        Ok(out.into_boxed_slice())
    }

    #[inline(never)]
    fn handle_force_close_abandoned_asset<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        close_q: u128,
    ) -> ProgramResult {
        let cranker = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let account_a_ai = account(accounts, 2)?;
        let account_b_ai = account(accounts, 3)?;
        expect_signer(cranker)?;
        expect_writable(market_ai)?;
        expect_writable(account_a_ai)?;
        expect_writable(account_b_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(account_a_ai, program_id)?;
        expect_owner(account_b_ai, program_id)?;
        if account_a_ai.key == account_b_ai.key || close_q == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let (_, mode_pre, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        ensure_portfolio_storage_for_market_slots(account_a_ai, max_market_slots)?;
        ensure_portfolio_storage_for_market_slots(account_b_ai, max_market_slots)?;

        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
        if group.header.mode != 0
            || asset_index_usize >= group.header.config.max_market_slots.get() as usize
            || asset_index_usize >= group.markets.len()
            || cfg.force_close_delay_slots == 0
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let asset = group.markets[asset_index_usize].engine.asset;
        if asset.lifecycle != ASSET_LIFECYCLE_RECOVERY {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
        let shutdown_slot = profile.last_good_oracle_slot;
        if shutdown_slot == 0
            || authenticated_slot < shutdown_slot
            || authenticated_slot.saturating_sub(shutdown_slot) < cfg.force_close_delay_slots
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let frozen_mark = asset.effective_price.get();
        if frozen_mark == 0 || frozen_mark > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::OracleInvalid.into());
        }

        let mut account_a_data = account_a_ai.try_borrow_mut_data()?;
        let mut account_b_data = account_b_ai.try_borrow_mut_data()?;
        let mut account_a =
            state::portfolio_view_mut_for_market_slots(&mut account_a_data, max_market_slots)?;
        let mut account_b =
            state::portfolio_view_mut_for_market_slots(&mut account_b_data, max_market_slots)?;
        expect_portfolio_view_account_key(&account_a, account_a_ai.key)?;
        expect_portfolio_view_account_key(&account_b, account_b_ai.key)?;
        account_a
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)?;
        account_b
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)?;
        let leg_a = active_leg_for_asset_view(&account_a, asset_index_usize)?;
        let leg_b = active_leg_for_asset_view(&account_b, asset_index_usize)?;
        if leg_a.side == leg_b.side {
            return Err(PercolatorError::EngineInvalidLeg.into());
        }
        let close_q = close_q
            .min(leg_a.basis_pos_q.unsigned_abs())
            .min(leg_b.basis_pos_q.unsigned_abs());
        if close_q == 0 {
            return Err(PercolatorError::EngineNonProgress.into());
        }
        let req = TradeRequestV16 {
            asset_index: asset_index_usize,
            // signed size_q; force-close direction is carried by the long/short orientation
            // selected just below, so pass the positive close magnitude here.
            size_q: close_q as i128,
            exec_price: frozen_mark,
            fee_bps: 0,
        };
        // Taker-only: this path always trades at fee_bps: 0 (a cranker-driven
        // forced close, not a fee-bearing trade), so `taker_is_long_account`
        // is a documented no-op here -- `charge_account_fee_current_not_atomic`
        // short-circuits on `requested_fee == 0` regardless of which side is
        // nominally "taker" (design §1A.4).
        if leg_a.side == SideV16::Short {
            group
                .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                    &mut account_a,
                    &mut account_b,
                    req,
                    true,
                )
                .map_err(map_v16_error)?;
        } else {
            group
                .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                    &mut account_b,
                    &mut account_a,
                    req,
                    true,
                )
                .map_err(map_v16_error)?;
        }
        group.validate_shape().map_err(map_v16_error)?;
        account_a
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)?;
        account_b
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)
    }

    fn matcher_tail_start_or_verify_lp_config<'a>(
        account_b_ai: &AccountInfo<'a>,
        matcher_prog_key: &Pubkey,
        matcher_ctx_key: &Pubkey,
        matcher_delegate_key: &Pubkey,
    ) -> Result<usize, ProgramError> {
        let cfg = state::read_portfolio_matcher_config(&account_b_ai.try_borrow_data()?)?;
        if cfg.enabled != 1
            || cfg.matcher_program != matcher_prog_key.to_bytes()
            || cfg.matcher_context != matcher_ctx_key.to_bytes()
            || cfg.matcher_delegate != matcher_delegate_key.to_bytes()
        {
            return Err(PercolatorError::Unauthorized.into());
        }
        Ok(7)
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_matcher_tail<'a>(
        tail: &'a [AccountInfo<'a>],
        signer_a_ai: &AccountInfo,
        market_ai: &AccountInfo,
        account_a_ai: &AccountInfo,
        account_b_ai: &AccountInfo,
        matcher_prog: &AccountInfo,
        matcher_ctx: &AccountInfo,
        matcher_delegate: &AccountInfo,
        program_id: &Pubkey,
    ) -> ProgramResult {
        if tail.len() > constants::MAX_MATCHER_TAIL_ACCOUNTS {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        for ai in tail {
            // FIX W1 (upstream #152, CRITICAL): a tail account forwarded to the untrusted
            // external matcher previously carried its `is_signer` flag verbatim. A hostile
            // matcher could re-list the taker's own wallet (or any other signer) in the tail
            // and use its forwarded signer privilege in a nested CPI (e.g. a System Program
            // transfer) before returning an otherwise-valid fill -- wallet-drain-grade, zero
            // privilege required beyond routing a trade through a malicious LP-registered
            // matcher. Reject any tail entry that is a signer, and (matching upstream) also
            // reject aliasing any of the trusted accounts this call already knows about.
            if ai.is_signer
                || ai.key == signer_a_ai.key
                || ai.key == market_ai.key
                || ai.key == account_a_ai.key
                || ai.key == account_b_ai.key
                || ai.key == matcher_prog.key
                || ai.key == matcher_ctx.key
                || ai.key == matcher_delegate.key
                || ai.key == program_id
                || ai.owner == program_id
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn handle_trade_cpi<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        size_q: i128,
        fee_bps: u64,
        limit_price: u64,
    ) -> ProgramResult {
        let signer_a = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let account_a_ai = account(accounts, 2)?;
        let account_b_ai = account(accounts, 3)?;
        let matcher_prog = account(accounts, 4)?;
        let matcher_ctx = account(accounts, 5)?;
        let matcher_delegate = account(accounts, 6)?;

        expect_signer(signer_a)?;
        expect_writable(market_ai)?;
        expect_writable(account_a_ai)?;
        expect_writable(account_b_ai)?;
        expect_writable(matcher_ctx)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(account_a_ai, program_id)?;
        expect_owner(account_b_ai, program_id)?;
        if account_a_ai.key == account_b_ai.key
            || matcher_prog.key == program_id
            || !matcher_prog.executable
            || matcher_ctx.executable
            || matcher_ctx.owner != matcher_prog.key
            || matcher_ctx.data_len() < constants::MATCHER_CONTEXT_MIN_LEN
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let (cfg_pre, mode_pre, current_slot_pre, oracle_price, max_trading_fee_bps) =
            state::read_market_trade_preflight(
                &market_ai.try_borrow_data()?,
                asset_index as usize,
            )?;
        let (account_a_header, account_a_owner) =
            state::read_portfolio_owner_preflight(&account_a_ai.try_borrow_data()?)?;
        let (account_b_header, account_b_owner) =
            state::read_portfolio_owner_preflight(&account_b_ai.try_borrow_data()?)?;
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let oracle_profile_pre = read_oracle_profile_for_asset(
            &market_ai.try_borrow_data()?,
            &cfg_pre,
            asset_index as usize,
        )?;
        let stale_matured = global_or_profile_resolve_matured_at_slot(
            &cfg_pre,
            &oracle_profile_pre,
            authenticated_slot_or_fallback(current_slot_pre),
        );
        if stale_matured {
            return Err(PercolatorError::OracleStale.into());
        }
        let fee_floor_pre = core::cmp::max(fee_bps, cfg_pre.trade_fee_base_bps);
        if fee_floor_pre > max_trading_fee_bps {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if account_a_header.portfolio_account_id != account_a_ai.key.to_bytes()
            || account_b_header.portfolio_account_id != account_b_ai.key.to_bytes()
        {
            return Err(PercolatorError::EngineProvenanceMismatch.into());
        }
        // E2: the taker (account_a) — owner==signer OR signer holds the bound NFT.
        // Pre-view path: use the scalar auth core with the preflight (owner, market_group).
        // Optional trailing accounts [7]=nft_registry [8]=PositionNft PDA [9]=signer NFT ATA.
        let nft = optional_nft_holder_accounts(accounts, 7);
        authorize_owner_or_nft_holder_raw(
            &account_a_owner,
            account_a_ai.key,
            &account_a_header.market_group_id,
            signer_a.key,
            nft,
            program_id,
        )?;
        let account_b_owner_key = Pubkey::new_from_array(account_b_owner);
        let (delegate, bump) = derive_matcher_delegate(
            program_id,
            market_ai.key,
            account_b_ai.key,
            &account_b_owner_key,
            matcher_prog.key,
            matcher_ctx.key,
        );
        expect_key(matcher_delegate, &delegate)?;
        let tail_start = matcher_tail_start_or_verify_lp_config(
            account_b_ai,
            matcher_prog.key,
            matcher_ctx.key,
            matcher_delegate.key,
        )?;
        let tail = accounts
            .get(tail_start..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        validate_matcher_tail(
            tail,
            signer_a,
            market_ai,
            account_a_ai,
            account_b_ai,
            matcher_prog,
            matcher_ctx,
            matcher_delegate,
            program_id,
        )?;
        if size_q == 0 || size_q == i128::MIN {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if oracle_price == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let req_id = state::next_market_matcher_req_id(&market_ai.try_borrow_data()?)?;
        let lp_account_id = matcher_lp_account_id(&delegate);
        let (_, _, max_market_slots_pre, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_cpi_trade_asset_lifecycle_before_matcher_from_accounts(
            market_ai,
            account_a_ai,
            account_b_ai,
            max_market_slots_pre,
            &[(asset_index, size_q)],
        )?;

        invoke_matcher(
            matcher_prog,
            matcher_ctx,
            matcher_delegate,
            tail,
            req_id,
            asset_index,
            lp_account_id,
            oracle_price,
            size_q,
            &[
                b"matcher",
                market_ai.key.as_ref(),
                account_b_ai.key.as_ref(),
                account_b_owner_key.as_ref(),
                matcher_prog.key.as_ref(),
                matcher_ctx.key.as_ref(),
                &[bump],
            ],
        )?;

        let ret = {
            let data = matcher_ctx.try_borrow_data()?;
            matcher_abi::read_matcher_return(&data)?
        };
        matcher_abi::validate_matcher_return(
            &ret,
            lp_account_id,
            asset_index,
            oracle_price,
            size_q,
            req_id,
        )?;
        if limit_price != 0 {
            let limit_ok = if size_q > 0 {
                ret.exec_price_e6 <= limit_price
            } else {
                ret.exec_price_e6 >= limit_price
            };
            if !limit_ok {
                return Err(PercolatorError::InvalidInstruction.into());
            }
        }
        if ret.exec_size == 0 {
            state::commit_market_matcher_req_id(&mut market_ai.try_borrow_mut_data()?, req_id)?;
            return Ok(());
        }
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        handle_trade_nocpi_zero_copy(
            program_id,
            signer_a.key,
            &account_b_owner_key,
            market_ai,
            account_a_ai,
            account_b_ai,
            asset_index,
            ret.exec_size,
            ret.exec_price_e6,
            fee_bps,
            max_market_slots,
        )?;
        state::commit_market_matcher_req_id(&mut market_ai.try_borrow_mut_data()?, req_id)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_set_matcher_config<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        enabled: u8,
    ) -> ProgramResult {
        if enabled > 1 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let lp_owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let lp_portfolio_ai = account(accounts, 2)?;
        expect_signer(lp_owner)?;
        expect_writable(lp_portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(lp_portfolio_ai, program_id)?;
        let (header, owner) =
            state::read_portfolio_owner_preflight(&lp_portfolio_ai.try_borrow_data()?)?;
        if header.market_group_id != market_ai.key.to_bytes()
            || header.portfolio_account_id != lp_portfolio_ai.key.to_bytes()
            || owner != lp_owner.key.to_bytes()
        {
            return Err(PercolatorError::Unauthorized.into());
        }
        let required_len = state::portfolio_account_len_for_market_slots(0)?;
        if lp_portfolio_ai.data_len() < required_len {
            lp_portfolio_ai.realloc(required_len, true)?;
        }
        let cfg = if enabled == 0 {
            state::PortfolioMatcherConfigV16::default()
        } else {
            let matcher_prog = account(accounts, 3)?;
            let matcher_ctx = account(accounts, 4)?;
            let matcher_delegate = account(accounts, 5)?;
            if matcher_prog.key == program_id
                || !matcher_prog.executable
                || matcher_ctx.executable
                || matcher_ctx.owner != matcher_prog.key
                || matcher_ctx.data_len() < constants::MATCHER_CONTEXT_MIN_LEN
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let (delegate, _) = derive_matcher_delegate(
                program_id,
                market_ai.key,
                lp_portfolio_ai.key,
                lp_owner.key,
                matcher_prog.key,
                matcher_ctx.key,
            );
            expect_key(matcher_delegate, &delegate)?;
            state::PortfolioMatcherConfigV16 {
                matcher_program: matcher_prog.key.to_bytes(),
                matcher_context: matcher_ctx.key.to_bytes(),
                matcher_delegate: matcher_delegate.key.to_bytes(),
                enabled: 1,
            }
        };
        state::write_portfolio_matcher_config(&mut lp_portfolio_ai.try_borrow_mut_data()?, &cfg)
    }

    /// InitMatcherCtx (tag 83) — bootstrap a matcher context via CPI.
    ///
    /// This is the only path that can call the matcher's tag-2 `process_init` with the
    /// `matcher_delegate` PDA as signer — a PDA cannot sign top-level transactions, so
    /// only an `invoke_signed` from this wrapper can supply the required signature.
    ///
    /// Pre-conditions (checked here):
    ///   - `lp_owner` is a signer
    ///   - `market_ai` is owned by this program
    ///   - `lp_portfolio_ai` is owned by this program and its recorded owner matches `lp_owner`
    ///   - `matcher_ctx` is owned by `matcher_prog` and is writable with len >= MATCHER_CONTEXT_MIN_LEN
    ///   - `matcher_prog` is executable
    ///   - `matcher_delegate` matches the PDA derived from the six seeds
    ///   - The LP portfolio's stored matcher config matches the supplied accounts (via
    ///     `matcher_tail_start_or_verify_lp_config`), ensuring the LP owner cannot
    ///     bootstrap a context for an arbitrary matcher — only the one they previously
    ///     registered via SetMatcherConfig
    ///
    /// After this instruction the matcher program's `process_init` has written the
    /// `MatcherCtx` into `matcher_ctx`, and subsequent `TradeCpi`/`BatchTradeCpi`
    /// calls will succeed.
    ///
    /// Ported verbatim from percolator-prog@6ca7b97b so the wire format, account
    /// list, and behavior byte-match the deployed program (DECISIONS-LEDGER.md
    /// "Pinned deployed revisions").
    ///
    /// Accounts:
    ///   0  lp_owner       [signer]           — owns the LP portfolio
    ///   1  market_ai      [ro]               — wrapper-owned market account
    ///   2  lp_portfolio   [ro]               — LP's portfolio (provenance checked)
    ///   3  matcher_ctx    [writable]         — matcher context account to initialise
    ///   4  matcher_prog   [ro, executable]   — the matcher program
    ///   5  matcher_delegate [ro]             — `["matcher", market, lp_portfolio,
    ///                                          lp_owner, matcher_prog, matcher_ctx]`
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn handle_init_matcher_ctx<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        kind: u8,
        trading_fee_bps: u32,
        base_spread_bps: u32,
        max_total_bps: u32,
        impact_k_bps: u32,
        liquidity_notional_e6: u128,
        max_fill_abs: u128,
        max_inventory_abs: u128,
        fee_to_insurance_bps: u16,
        skew_spread_mult_bps: u16,
    ) -> ProgramResult {
        if accounts.len() < 6 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let lp_owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let lp_portfolio_ai = account(accounts, 2)?;
        let matcher_ctx = account(accounts, 3)?;
        let matcher_prog = account(accounts, 4)?;
        let matcher_delegate = account(accounts, 5)?;

        // Caller must sign.
        expect_signer(lp_owner)?;
        // matcher_ctx must be writable (it will be written by the matcher CPI).
        expect_writable(matcher_ctx)?;
        // Verify wrapper owns the market and LP portfolio accounts.
        expect_owner(market_ai, program_id)?;
        expect_owner(lp_portfolio_ai, program_id)?;

        // Verify LP portfolio is valid and caller owns it.
        let (portfolio_header, portfolio_owner) =
            state::read_portfolio_owner_preflight(&lp_portfolio_ai.try_borrow_data()?)?;
        if portfolio_header.portfolio_account_id != lp_portfolio_ai.key.to_bytes() {
            return Err(PercolatorError::EngineProvenanceMismatch.into());
        }
        if portfolio_header.market_group_id != market_ai.key.to_bytes() {
            return Err(PercolatorError::EngineProvenanceMismatch.into());
        }
        if portfolio_owner != lp_owner.key.to_bytes() {
            return Err(PercolatorError::Unauthorized.into());
        }

        // Validate matcher shape: must be executable, ctx owned by prog, right size.
        if matcher_prog.key == program_id
            || !matcher_prog.executable
            || matcher_ctx.executable
            || matcher_ctx.owner != matcher_prog.key
            || matcher_ctx.data_len() < constants::MATCHER_CONTEXT_MIN_LEN
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        // Derive the delegate PDA and verify the caller supplied the right account.
        let lp_owner_key = Pubkey::new_from_array(portfolio_owner);
        let (delegate, bump) = derive_matcher_delegate(
            program_id,
            market_ai.key,
            lp_portfolio_ai.key,
            &lp_owner_key,
            matcher_prog.key,
            matcher_ctx.key,
        );
        expect_key(matcher_delegate, &delegate)?;

        // Verify the LP's stored matcher config matches — this prevents an LP owner
        // from re-initializing with a different (matcher_prog, matcher_ctx) pair than
        // they registered via SetMatcherConfig.
        matcher_tail_start_or_verify_lp_config(
            lp_portfolio_ai,
            matcher_prog.key,
            matcher_ctx.key,
            matcher_delegate.key,
        )?;

        // The lp_account_id stored in the matcher context is the first 8 bytes of
        // the delegate PDA — the same value used in every subsequent TradeCpi call.
        let lp_account_id = matcher_lp_account_id(&delegate);

        // Build the 78-byte matcher init payload (tag=2, InitParams layout).
        // Byte layout:
        //   [0]     MATCHER_INIT_VAMM_TAG = 2
        //   [1]     kind
        //   [2..6]  trading_fee_bps (u32 le)
        //   [6..10] base_spread_bps (u32 le)
        //   [10..14] max_total_bps (u32 le)
        //   [14..18] impact_k_bps (u32 le)
        //   [18..34] liquidity_notional_e6 (u128 le)
        //   [34..50] max_fill_abs (u128 le)
        //   [50..66] max_inventory_abs (u128 le)
        //   [66..68] fee_to_insurance_bps (u16 le)
        //   [68..70] skew_spread_mult_bps (u16 le)
        //   [70..78] lp_account_id (u64 le)
        let mut cpi_data = [0u8; 78];
        cpi_data[0] = 2; // MATCHER_INIT_VAMM_TAG
        cpi_data[1] = kind;
        cpi_data[2..6].copy_from_slice(&trading_fee_bps.to_le_bytes());
        cpi_data[6..10].copy_from_slice(&base_spread_bps.to_le_bytes());
        cpi_data[10..14].copy_from_slice(&max_total_bps.to_le_bytes());
        cpi_data[14..18].copy_from_slice(&impact_k_bps.to_le_bytes());
        cpi_data[18..34].copy_from_slice(&liquidity_notional_e6.to_le_bytes());
        cpi_data[34..50].copy_from_slice(&max_fill_abs.to_le_bytes());
        cpi_data[50..66].copy_from_slice(&max_inventory_abs.to_le_bytes());
        cpi_data[66..68].copy_from_slice(&fee_to_insurance_bps.to_le_bytes());
        cpi_data[68..70].copy_from_slice(&skew_spread_mult_bps.to_le_bytes());
        cpi_data[70..78].copy_from_slice(&lp_account_id.to_le_bytes());

        // matcher's process_init accounts: [lp_pda (signer), ctx_account (writable)]
        let metas = [
            AccountMeta::new_readonly(*matcher_delegate.key, true),
            AccountMeta::new(*matcher_ctx.key, false),
        ];
        let ix = SolInstruction {
            program_id: *matcher_prog.key,
            accounts: metas.to_vec(),
            data: cpi_data.to_vec(),
        };

        // Signs the CPI as the delegate PDA using invoke_signed.
        let bump_arr = [bump];
        let seeds: &[&[u8]] = &[
            b"matcher",
            market_ai.key.as_ref(),
            lp_portfolio_ai.key.as_ref(),
            lp_owner_key.as_ref(),
            matcher_prog.key.as_ref(),
            matcher_ctx.key.as_ref(),
            &bump_arr,
        ];
        invoke_signed(
            &ix,
            &[matcher_delegate.clone(), matcher_ctx.clone(), matcher_prog.clone()],
            &[seeds],
        )
    }

    /// Maximum legs in a single matcher batch CPI: the matcher returns N*64 bytes via
    /// `set_return_data`, bounded by Solana's 1024-byte return-data cap.
    /// Maximum legs in one BatchTradeCpi / BatchTradeNoCpi.
    ///
    /// LOWERED 16 -> 11 for #436 (2026-08-29), on MEASUREMENT rather than estimate. Sweeping the
    /// two axes independently against the deployed program, with the tail held at 1:
    ///
    /// ```text
    /// 2 legs    441,854 CU        10 legs  1,194,739 CU
    /// 4 legs    585,796 CU        11 legs  1,332,184 CU   <- the most that fits
    /// 8 legs    960,738 CU        12 legs  CU EXHAUSTED
    /// ```
    ///
    /// A leg costs ~120,000 CU; a tail account ~840 CU — about 140x apart. So the sibling
    /// `MATCHER_BATCH_TAIL_FANOUT_BUDGET` (legs * tail <= 64) bounds the WRONG QUANTITY: a
    /// product of 12 (12 legs x 1 tail) FAILS while a product of 64 (4 legs x 16 tail) succeeds
    /// comfortably at 596,913 CU. No value of a product budget is simultaneously safe and
    /// useful — lowering it to 11 to catch 12x1 would forbid 4x16, which works.
    ///
    /// 12..=16 could therefore NEVER succeed. Advertising them was a lie that cost callers an
    /// opaque failure: pass the declared check, then die on compute with
    /// ProgramFailedToComplete. Lowering to 11 forbids nothing that works and converts that into
    /// an immediate, attributable InvalidInstruction.
    ///
    /// NECESSARY, NOT SUFFICIENT. Per-leg cost varies with market state, so 11 legs is not
    /// guaranteed to fit in every fixture — it is the ceiling observed in ours. Callers must
    /// still handle CU exhaustion below this bound; this only removes the range that is
    /// impossible everywhere.
    ///
    /// UPSTREAM DIVERGENCE, deliberate: aeyakovenko/percolator-prog still has 16. The product
    /// budget itself came FROM upstream (91129168 "Cap batch CPI matcher tail fanout"), so this
    /// defect exists there too and no upstream branch bounds the leg count. Worth sending back.
    const MATCHER_BATCH_MAX_LEGS: usize = 11;
    // W4 [HIGH]: legs.len()<=16 and tail.len()<=32 are each bounded independently, but their
    // PRODUCT (up to 512) is not -- a batch with many legs AND a full matcher tail multiplies
    // per-leg tail-account validation/CPI-account-resolution work, blowing the CU budget before
    // any single guard fires. Cap the product directly (upstream wrapper 449e7d55, #145).
    const MATCHER_BATCH_TAIL_FANOUT_BUDGET: usize = constants::MAX_MATCHER_TAIL_ACCOUNTS * 2;

    #[allow(clippy::too_many_arguments)]
    fn invoke_matcher_batch<'a>(
        matcher_prog: &AccountInfo<'a>,
        matcher_ctx: &AccountInfo<'a>,
        matcher_delegate: &AccountInfo<'a>,
        tail: &[AccountInfo<'a>],
        req_id: u64,
        lp_account_id: u64,
        // (asset_index, oracle_price_e6, signed req_size) per leg
        legs: &[(u16, u64, i128)],
        seeds: &[&[u8]],
    ) -> ProgramResult {
        let mut data = Vec::with_capacity(18 + legs.len() * 26);
        data.push(3u8);
        data.push(legs.len() as u8);
        data.extend_from_slice(&req_id.to_le_bytes());
        data.extend_from_slice(&lp_account_id.to_le_bytes());
        for (asset_index, oracle_price_e6, req_size) in legs {
            data.extend_from_slice(&asset_index.to_le_bytes());
            data.extend_from_slice(&oracle_price_e6.to_le_bytes());
            data.extend_from_slice(&req_size.to_le_bytes());
        }
        let mut metas = Vec::with_capacity(2 + tail.len());
        metas.push(AccountMeta::new_readonly(*matcher_delegate.key, true));
        metas.push(AccountMeta::new(*matcher_ctx.key, false));
        for ai in tail {
            if ai.is_writable {
                metas.push(AccountMeta::new(*ai.key, ai.is_signer));
            } else {
                metas.push(AccountMeta::new_readonly(*ai.key, ai.is_signer));
            }
        }
        let ix = SolInstruction {
            program_id: *matcher_prog.key,
            accounts: metas,
            data,
        };
        let mut infos = Vec::with_capacity(3 + tail.len());
        infos.push(matcher_delegate.clone());
        infos.push(matcher_ctx.clone());
        infos.push(matcher_prog.clone());
        for ai in tail {
            infos.push(ai.clone());
        }
        invoke_signed(&ix, &infos, &[seeds])
    }

    /// Atomic multi-leg batch routed through one external matcher. A single batched matcher CPI
    /// fills every leg against the LP (account_b), the per-leg returns are validated under the same
    /// anti-spoof binding as the single-fill path, and all fills then apply through the batch
    /// engine path with one end-state margin check.
    #[inline(never)]
    fn handle_batch_trade_cpi<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        legs: &[ix::BatchTradeCpiLeg],
    ) -> ProgramResult {
        if legs.is_empty() || legs.len() > MATCHER_BATCH_MAX_LEGS {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let signer_a = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let account_a_ai = account(accounts, 2)?;
        let account_b_ai = account(accounts, 3)?;
        let matcher_prog = account(accounts, 4)?;
        let matcher_ctx = account(accounts, 5)?;
        let matcher_delegate = account(accounts, 6)?;

        expect_signer(signer_a)?;
        expect_writable(market_ai)?;
        expect_writable(account_a_ai)?;
        expect_writable(account_b_ai)?;
        expect_writable(matcher_ctx)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(account_a_ai, program_id)?;
        expect_owner(account_b_ai, program_id)?;
        if account_a_ai.key == account_b_ai.key
            || matcher_prog.key == program_id
            || !matcher_prog.executable
            || matcher_ctx.executable
            || matcher_ctx.owner != matcher_prog.key
            || matcher_ctx.data_len() < constants::MATCHER_CONTEXT_MIN_LEN
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        // Preflight: market must be Live, the taker owner must sign, and each leg's oracle price
        // is read for matcher request/return binding.
        let mut asset_indices: Vec<u16> = Vec::with_capacity(legs.len());
        for leg in legs {
            if leg.size_q == 0 || leg.size_q == i128::MIN {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            asset_indices.push(leg.asset_index);
        }
        // One header/config parse for mode + slot + every leg's oracle price (avoids O(N^2)
        // re-parsing the market once per leg). W7: also gate the whole batch on base-or-profile
        // permissionless-resolve stale maturity BEFORE the matcher CPI -- same predicate as the
        // single-leg TradeCpi preflight and the shared trade/crank helper, so a stale base oracle
        // freezes non-base legs too and a hostile matcher is never invoked once the market has
        // matured stale (previously this preflight had NO staleness gate at all; staleness was
        // only caught after the CPI returned, inside handle_batch_execute_zero_copy).
        let (mode_pre, oracle_prices, stale_matured) = {
            let market_data = market_ai.try_borrow_data()?;
            let (cfg_pre, mode_pre, current_slot_pre, oracle_prices) =
                state::read_asset_effective_prices(&market_data, &asset_indices)?;
            let authenticated_slot = authenticated_slot_or_fallback(current_slot_pre);
            let mut stale_matured = false;
            for &asset_index in &asset_indices {
                let oracle_profile_pre =
                    read_oracle_profile_for_asset(&market_data, &cfg_pre, asset_index as usize)?;
                if global_or_profile_resolve_matured_at_slot(
                    &cfg_pre,
                    &oracle_profile_pre,
                    authenticated_slot,
                ) {
                    stale_matured = true;
                    break;
                }
            }
            (mode_pre, oracle_prices, stale_matured)
        };
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if stale_matured {
            return Err(PercolatorError::OracleStale.into());
        }
        let (account_a_header, account_a_owner) =
            state::read_portfolio_owner_preflight(&account_a_ai.try_borrow_data()?)?;
        let (account_b_header, account_b_owner) =
            state::read_portfolio_owner_preflight(&account_b_ai.try_borrow_data()?)?;
        if account_a_header.portfolio_account_id != account_a_ai.key.to_bytes()
            || account_b_header.portfolio_account_id != account_b_ai.key.to_bytes()
        {
            return Err(PercolatorError::EngineProvenanceMismatch.into());
        }
        // E2: the taker (account_a) — owner==signer OR signer holds the bound NFT.
        // Pre-view path: use the scalar auth core with the preflight (owner, market_group).
        // Optional trailing accounts [7]=nft_registry [8]=PositionNft PDA [9]=signer NFT ATA.
        let nft = optional_nft_holder_accounts(accounts, 7);
        authorize_owner_or_nft_holder_raw(
            &account_a_owner,
            account_a_ai.key,
            &account_a_header.market_group_id,
            signer_a.key,
            nft,
            program_id,
        )?;
        let account_b_owner_key = Pubkey::new_from_array(account_b_owner);
        let (delegate, bump) = derive_matcher_delegate(
            program_id,
            market_ai.key,
            account_b_ai.key,
            &account_b_owner_key,
            matcher_prog.key,
            matcher_ctx.key,
        );
        expect_key(matcher_delegate, &delegate)?;
        let tail_start = matcher_tail_start_or_verify_lp_config(
            account_b_ai,
            matcher_prog.key,
            matcher_ctx.key,
            matcher_delegate.key,
        )?;
        let tail = accounts
            .get(tail_start..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        validate_matcher_tail(
            tail,
            signer_a,
            market_ai,
            account_a_ai,
            account_b_ai,
            matcher_prog,
            matcher_ctx,
            matcher_delegate,
            program_id,
        )?;
        if legs.len().saturating_mul(tail.len()) > MATCHER_BATCH_TAIL_FANOUT_BUDGET {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let req_id = state::next_market_matcher_req_id(&market_ai.try_borrow_data()?)?;
        let lp_account_id = matcher_lp_account_id(&delegate);

        // Build the matcher batch request: per leg, (asset, that asset's oracle price, signed size).
        let mut matcher_legs: Vec<(u16, u64, i128)> = Vec::with_capacity(legs.len());
        let mut cpi_requests: Vec<(u16, i128)> = Vec::with_capacity(legs.len());
        for (i, leg) in legs.iter().enumerate() {
            if oracle_prices[i] == 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            matcher_legs.push((leg.asset_index, oracle_prices[i], leg.size_q));
            cpi_requests.push((leg.asset_index, leg.size_q));
        }
        let (_, _, max_market_slots_pre, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_cpi_trade_asset_lifecycle_before_matcher_from_accounts(
            market_ai,
            account_a_ai,
            account_b_ai,
            max_market_slots_pre,
            &cpi_requests,
        )?;

        invoke_matcher_batch(
            matcher_prog,
            matcher_ctx,
            matcher_delegate,
            tail,
            req_id,
            lp_account_id,
            &matcher_legs,
            &[
                b"matcher",
                market_ai.key.as_ref(),
                account_b_ai.key.as_ref(),
                account_b_owner_key.as_ref(),
                matcher_prog.key.as_ref(),
                matcher_ctx.key.as_ref(),
                &[bump],
            ],
        )?;

        // Read the N back-to-back returns the matcher emitted via set_return_data.
        let (ret_program, ret_data) = solana_program::program::get_return_data()
            .ok_or(PercolatorError::InvalidInstruction)?;
        if ret_program != *matcher_prog.key
            || ret_data.len() != legs.len() * matcher_abi::MATCHER_RETURN_BYTES
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let mut exec_legs: Vec<ix::BatchTradeLeg> = Vec::with_capacity(legs.len());
        for (i, leg) in legs.iter().enumerate() {
            let chunk = &ret_data[i * matcher_abi::MATCHER_RETURN_BYTES
                ..(i + 1) * matcher_abi::MATCHER_RETURN_BYTES];
            let ret = matcher_abi::read_matcher_return(chunk)?;
            matcher_abi::validate_matcher_return(
                &ret,
                lp_account_id,
                leg.asset_index,
                oracle_prices[i],
                leg.size_q,
                req_id,
            )?;
            // Atomic strategy semantics: every leg must fill (no zero/skip fills in a batch).
            if ret.exec_size == 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            if leg.limit_price != 0 {
                let limit_ok = if leg.size_q > 0 {
                    ret.exec_price_e6 <= leg.limit_price
                } else {
                    ret.exec_price_e6 >= leg.limit_price
                };
                if !limit_ok {
                    return Err(PercolatorError::InvalidInstruction.into());
                }
            }
            exec_legs.push(ix::BatchTradeLeg {
                asset_index: leg.asset_index,
                size_q: ret.exec_size,
                exec_price: ret.exec_price_e6,
                fee_bps: leg.fee_bps,
            });
        }

        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        handle_batch_execute_zero_copy(
            program_id,
            signer_a.key,
            &account_b_owner_key,
            market_ai,
            account_a_ai,
            account_b_ai,
            &exec_legs,
            max_market_slots,
        )?;
        state::commit_market_matcher_req_id(&mut market_ai.try_borrow_mut_data()?, req_id)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_close_portfolio<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let closer = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_signer(closer)?;
        expect_writable(closer)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            let owner_signed = portfolio.header.owner == closer.key.to_bytes();
            let terminal_marketauth_cleanup =
                group.header.mode == 1 && live_authority_matches(&cfg.marketauth, closer.key);
            if !owner_signed && !terminal_marketauth_cleanup {
                return Err(PercolatorError::Unauthorized.into());
            }
            portfolio
                .validate_with_market(&group.as_view())
                .map_err(map_v16_error)?;
            group
                .deregister_empty_materialized_portfolio_not_atomic(&portfolio.as_view())
                .map_err(map_v16_error)?;
        }
        close_portfolio_account_to_market_slab(portfolio_ai, closer)?;
        Ok(())
    }

    /// F-1: insurance-withdrawal cooldown gate. `last_slot == 0` means "never withdrawn", so the
    /// first withdrawal is always allowed. Returns `InsuranceWithdrawCooldownActive` when a
    /// non-zero cooldown is configured and the window has not yet elapsed. Pure: no I/O.
    #[inline]
    pub fn check_insurance_withdraw_cooldown(
        cooldown_slots: u64,
        last_slot: u64,
        now_slot: u64,
    ) -> Result<(), ProgramError> {
        if cooldown_slots > 0 && last_slot != 0 {
            let earliest = last_slot
                .checked_add(cooldown_slots)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            if now_slot < earliest {
                return Err(PercolatorError::InsuranceWithdrawCooldownActive.into());
            }
        }
        Ok(())
    }

    /// F-2: deposits-only withdrawal ceiling. When `deposits_only != 0`, `amount` may not exceed
    /// `deposit_remaining`; the decremented remaining is returned. When disabled, `deposit_remaining`
    /// is returned unchanged. Returns `InsuranceWithdrawCeilingExceeded` if `amount` exceeds the
    /// remaining deposited principal. Pure: no I/O.
    #[inline]
    pub fn apply_insurance_withdraw_ceiling(
        deposits_only: u8,
        deposit_remaining: u128,
        amount: u128,
    ) -> Result<u128, ProgramError> {
        if deposits_only == 0 {
            return Ok(deposit_remaining);
        }
        if amount > deposit_remaining {
            return Err(PercolatorError::InsuranceWithdrawCeilingExceeded.into());
        }
        deposit_remaining
            .checked_sub(amount)
            .ok_or_else(|| PercolatorError::EngineCounterUnderflow.into())
    }

    #[inline(never)]
    fn handle_top_up_insurance<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let signer = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let source_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let token_program = account(accounts, 4)?;
        let ledger_ai = accounts.get(5);
        expect_signer(signer)?;
        expect_writable(market_ai)?;
        expect_writable(source_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        if let Some(ledger_ai) = ledger_ai {
            expect_writable(ledger_ai)?;
            expect_owner(ledger_ai, program_id)?;
        }
        verify_token_program(token_program)?;
        let (cfg_pre, mode, asset0_insurance_authority) = {
            let market_data = market_ai.try_borrow_data()?;
            let (cfg_pre, mode, _, _) = state::read_market_config_mode_and_capacity(&market_data)?;
            let profile0 = read_oracle_profile_for_asset(&market_data, &cfg_pre, 0)?;
            (cfg_pre, mode, profile0.insurance_authority)
        };
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        expect_live_authority(&asset0_insurance_authority, signer.key)?;
        let mint = primary_collateral_mint(&cfg_pre);
        let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
        verify_user_token_account(source_token, signer.key, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(source_token, amount_u64)?;
        let mut cfg_after = None;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            let asset0_insurance_authority =
                domain_authorities_from_view(&group, &cfg, 0)?.insurance_authority;
            expect_live_authority(&asset0_insurance_authority, signer.key)?;
            let mut ledger_data = if let Some(ledger_ai) = ledger_ai {
                Some(ledger_ai.try_borrow_mut_data()?)
            } else {
                None
            };
            let mut ledger_state = if let Some(data) = ledger_data.as_deref() {
                let (mut ledger, initialized) = read_or_new_insurance_ledger(
                    data,
                    market_ai.key.to_bytes(),
                    asset0_insurance_authority,
                    market_insurance_remaining_view(&group, 0)?,
                )?;
                sync_insurance_ledger(&mut ledger, market_insurance_remaining_view(&group, 0)?)?;
                Some((ledger, initialized))
            } else {
                None
            };
            deposit_market_zero_insurance_view(&mut group, amount)?;
            if let Some((ledger, _)) = ledger_state.as_mut() {
                ledger.total_principal_atoms = ledger
                    .total_principal_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.total_deposited_atoms = ledger
                    .total_deposited_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.last_observed_insurance_atoms = ledger
                    .last_observed_insurance_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            }
            if cfg.insurance_withdraw_deposits_only != 0 {
                cfg.insurance_withdraw_deposit_remaining = cfg
                    .insurance_withdraw_deposit_remaining
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                cfg_after = Some(cfg);
            }
            group.validate_shape().map_err(map_v16_error)?;
            if let (Some(data), Some((ledger, initialized))) =
                (ledger_data.as_deref_mut(), ledger_state.as_ref())
            {
                write_or_init_insurance_ledger(data, ledger, *initialized)?;
            }
        }
        transfer_tokens(token_program, source_token, vault_token, signer, amount_u64)?;
        if let Some(cfg) = cfg_after {
            state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn handle_top_up_insurance_domain<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
        amount: u128,
    ) -> ProgramResult {
        let signer = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let source_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let token_program = account(accounts, 4)?;
        let ledger_ai = accounts.get(5);
        expect_signer(signer)?;
        expect_writable(market_ai)?;
        expect_writable(source_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        if let Some(ledger_ai) = ledger_ai {
            expect_writable(ledger_ai)?;
            expect_owner(ledger_ai, program_id)?;
        }
        verify_token_program(token_program)?;
        let domain = domain as usize;
        let (cfg_pre, authorities) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, group) = state::market_view_mut(&mut market_data)?;
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            let asset_index = domain / 2;
            if group.header.mode != 0
                || domain >= configured_slots.saturating_mul(2)
                || asset_index >= configured_slots
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            require_domain_accepts_live_topup_view(&group, domain)?;
            let profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
            (cfg, authorities)
        };
        expect_live_authority(&authorities.insurance_authority, signer.key)?;
        let mint = primary_collateral_mint(&cfg_pre);
        let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
        verify_user_token_account(source_token, signer.key, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(source_token, amount_u64)?;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            require_domain_accepts_live_topup_view(&group, domain)?;
            let authorities = domain_authorities_from_view(&group, &cfg, domain)?;
            expect_live_authority(&authorities.insurance_authority, signer.key)?;
            let mut ledger_data = if let Some(ledger_ai) = ledger_ai {
                Some(ledger_ai.try_borrow_mut_data()?)
            } else {
                None
            };
            let mut ledger_state = if let Some(data) = ledger_data.as_deref() {
                let observed = domain_budget_remaining_view(&group, domain)?;
                let (mut ledger, initialized) = read_or_new_insurance_ledger(
                    data,
                    market_ai.key.to_bytes(),
                    authorities.insurance_authority,
                    observed,
                )?;
                sync_insurance_ledger(&mut ledger, observed)?;
                Some((ledger, initialized))
            } else {
                None
            };
            group
                .deposit_domain_insurance_not_atomic(domain, amount)
                .map_err(map_v16_error)?;
            if let Some((ledger, _)) = ledger_state.as_mut() {
                ledger.total_principal_atoms = ledger
                    .total_principal_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.total_deposited_atoms = ledger
                    .total_deposited_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.last_observed_insurance_atoms = ledger
                    .last_observed_insurance_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            }
            group.validate_shape().map_err(map_v16_error)?;
            if let (Some(data), Some((ledger, initialized))) =
                (ledger_data.as_deref_mut(), ledger_state.as_ref())
            {
                write_or_init_insurance_ledger(data, ledger, *initialized)?;
            }
        }
        transfer_tokens(token_program, source_token, vault_token, signer, amount_u64)?;
        Ok(())
    }

    fn backing_domain_parts_view(
        group: &state::MarketViewMutV16<'_>,
        domain: usize,
    ) -> Result<(SourceCreditStateV16, percolator::BackingBucketV16), ProgramError> {
        let max_markets = group.header.config.max_market_slots.get() as usize;
        let asset_index = domain / 2;
        if domain >= max_markets.saturating_mul(2) || asset_index >= group.markets.len() {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let slot = &group.markets[asset_index].engine;
        let (source_acc, bucket_acc) = if domain % 2 == 0 {
            (&slot.source_credit_long, &slot.backing_long)
        } else {
            (&slot.source_credit_short, &slot.backing_short)
        };
        Ok((
            source_acc.try_to_runtime().map_err(map_v16_error)?,
            bucket_acc.try_to_runtime().map_err(map_v16_error)?,
        ))
    }

    fn backing_unavailable_principal_atoms(
        bucket: &percolator::BackingBucketV16,
    ) -> Result<u128, ProgramError> {
        bucket
            .consumed_liened_backing_num
            .checked_add(bucket.impaired_liened_backing_num)
            .map(|v| v / BOUND_SCALE)
            .ok_or(PercolatorError::EngineArithmeticOverflow.into())
    }

    fn sync_backing_domain_ledger(
        ledger: &mut state::BackingDomainLedgerAccountV16,
        bucket: &percolator::BackingBucketV16,
    ) -> ProgramResult {
        let bucket_earnings_atoms = bucket.utilization_fee_earnings;
        if bucket_earnings_atoms >= ledger.last_observed_bucket_earnings_atoms {
            ledger.total_earnings_atoms = ledger
                .total_earnings_atoms
                .checked_add(bucket_earnings_atoms - ledger.last_observed_bucket_earnings_atoms)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        }
        ledger.last_observed_bucket_earnings_atoms = bucket_earnings_atoms;

        // Deterministic farm rewards are represented as capped counter transfers:
        // the backing bucket's unavailable-principal delta is the realized-loss cap
        // source, and `cumulative_loss_atoms` is the LP-side residual_received
        // counter that a farm snapshots. Recoveries are tracked separately and do
        // not decrement residual_received.
        let unavailable_atoms = backing_unavailable_principal_atoms(bucket)?;
        if unavailable_atoms >= ledger.last_observed_unavailable_principal_atoms {
            ledger.cumulative_loss_atoms = ledger
                .cumulative_loss_atoms
                .checked_add(unavailable_atoms - ledger.last_observed_unavailable_principal_atoms)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        } else {
            ledger.cumulative_recovery_atoms = ledger
                .cumulative_recovery_atoms
                .checked_add(ledger.last_observed_unavailable_principal_atoms - unavailable_atoms)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        }
        ledger.last_observed_unavailable_principal_atoms = unavailable_atoms;
        Ok(())
    }

    fn sync_insurance_ledger(
        ledger: &mut state::InsuranceLedgerAccountV16,
        insurance_atoms: u128,
    ) -> ProgramResult {
        if insurance_atoms >= ledger.last_observed_insurance_atoms {
            ledger.cumulative_profit_atoms = ledger
                .cumulative_profit_atoms
                .checked_add(insurance_atoms - ledger.last_observed_insurance_atoms)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        } else {
            ledger.cumulative_loss_atoms = ledger
                .cumulative_loss_atoms
                .checked_add(ledger.last_observed_insurance_atoms - insurance_atoms)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        }
        ledger.last_observed_insurance_atoms = insurance_atoms;
        Ok(())
    }

    /// The sibling domain of `domain` within the SAME asset: domain = asset*2 + side,
    /// so flipping the low bit flips the side and keeps the asset. The LP vault is
    /// authorised over both (the `backing_bucket_authority` it holds is per-ASSET).
    fn sibling_domain(domain: u16) -> u16 {
        domain ^ 1
    }

    /// One domain's contribution to LP-vault NAV, synced to its bucket first.
    /// An uninitialised ledger account contributes 0 — `read_or_new_backing_domain_ledger`
    /// returns a zeroed ledger whose watermarks match the bucket, so a domain the
    /// vault has never funded adds nothing rather than failing.
    fn lp_vault_domain_nav_atoms(
        group: &state::MarketViewMutV16<'_>,
        market_group: [u8; 32],
        authority: [u8; 32],
        domain: u16,
        fee_share_bps: u16,
        ledger_data: &[u8],
    ) -> Result<u128, ProgramError> {
        let (_, bucket) = backing_domain_parts_view(group, domain as usize)?;
        let (mut ledger, _) = read_or_new_backing_domain_ledger(
            ledger_data,
            market_group,
            authority,
            domain,
            &bucket,
        )?;
        sync_backing_domain_ledger(&mut ledger, &bucket)?;
        percolator::lp_vault::lp_vault_nav_atoms(
            ledger.total_principal_atoms,
            ledger.total_earnings_atoms,
            ledger.total_earnings_withdrawn_atoms,
            ledger.cumulative_loss_atoms,
            ledger.cumulative_recovery_atoms,
            fee_share_bps,
        )
        .map_err(map_v16_error)
    }

    /// One domain's AVAILABLE principal (principal net of impairment). Mirrors
    /// `lp_vault_nav_atoms`'s internals exactly, minus the earnings term.
    fn lp_vault_domain_available_principal_atoms(
        group: &state::MarketViewMutV16<'_>,
        market_group: [u8; 32],
        authority: [u8; 32],
        domain: u16,
        ledger_data: &[u8],
    ) -> Result<u128, ProgramError> {
        let (_, bucket) = backing_domain_parts_view(group, domain as usize)?;
        let (mut ledger, _) = read_or_new_backing_domain_ledger(
            ledger_data,
            market_group,
            authority,
            domain,
            &bucket,
        )?;
        sync_backing_domain_ledger(&mut ledger, &bucket)?;
        let net_impairment = ledger
            .cumulative_loss_atoms
            .checked_sub(ledger.cumulative_recovery_atoms)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        ledger
            .total_principal_atoms
            .checked_sub(net_impairment)
            .ok_or_else(|| PercolatorError::EngineCounterUnderflow.into())
    }

    /// AVAILABLE principal across BOTH domains. Must be summed alongside NAV: the
    /// redemption split is `principal_out = shares * available_principal / total_shares`
    /// and `earnings_out = atoms_out - principal_out`. Pairing a COMBINED nav with a
    /// SINGLE-pot available_principal inflates `earnings_out` by the sibling pot's
    /// principal, which then fails the earnings-availability gate and bricks the
    /// redemption. Both terms have to span the same set of pots.
    fn lp_vault_combined_available_principal_atoms(
        group: &state::MarketViewMutV16<'_>,
        market_group: [u8; 32],
        authority: [u8; 32],
        domain: u16,
        own_ledger_data: &[u8],
        sibling_ledger_data: &[u8],
    ) -> Result<u128, ProgramError> {
        let own = lp_vault_domain_available_principal_atoms(
            group, market_group, authority, domain, own_ledger_data,
        )?;
        let sib = lp_vault_domain_available_principal_atoms(
            group,
            market_group,
            authority,
            sibling_domain(domain),
            sibling_ledger_data,
        )?;
        own.checked_add(sib)
            .ok_or_else(|| PercolatorError::EngineArithmeticOverflow.into())
    }

    /// LP-vault NAV across BOTH domains of its asset.
    ///
    /// The vault's backing can sit in either pot (see RebalanceLpVaultBacking,
    /// tag 91), so pricing shares off `registry.domain` alone understates NAV by
    /// whatever sits in the sibling and mints incoming depositors free shares at
    /// existing holders' expense. Summing the two `lp_vault_nav_atoms` calls
    /// separately loses at most 1 atom to the `lp_earnings` floor versus summing
    /// the inputs first — that atom stays in the vault, which is the safe side.
    /// Atoms the LP-vault fee crank could harvest into NAV *right now* (#411).
    ///
    /// This is the SINGLE definition of that quantity. `handle_lp_vault_crank_fees` and
    /// `handle_deposit_to_lp_vault` both call it, deliberately: the deposit must be priced
    /// against exactly what a crank in the same slot would realize, and if the two ever
    /// computed it separately they would drift and reopen this bug.
    ///
    /// It is NOT `lp_fee_accrued - lp_fee_withdrawn`. That is the CLAIM, and three legs
    /// (protocol / LP / stake) share one surplus pool with no cross-leg accounting, so the
    /// claim is only realizable down to whatever the engine and the vault can actually
    /// cover. Pricing against the unclamped claim would overstate NAV whenever the surplus
    /// is dry — trading one mispricing for another, in the opposite direction.
    fn lp_vault_harvestable_fee_atoms(
        cfg: &state::WrapperConfigV16,
        group: &state::MarketViewMutV16<'_>,
    ) -> Result<u128, ProgramError> {
        let claim_capacity = cfg
            .lp_fee_accrued_atoms
            .checked_sub(cfg.lp_fee_withdrawn_atoms)
            .ok_or(PercolatorError::EngineCounterUnderflow)?;
        let engine_available = group
            .header
            .insurance
            .get()
            .saturating_sub(group.header.source_insurance_credit_reserved_total_atoms.get())
            .saturating_sub(group.header.insurance_domain_budget_remaining_total.get());
        Ok(claim_capacity
            .min(engine_available)
            .min(group.header.vault.get()))
    }

    fn lp_vault_combined_nav_atoms(
        group: &state::MarketViewMutV16<'_>,
        market_group: [u8; 32],
        authority: [u8; 32],
        domain: u16,
        fee_share_bps: u16,
        own_ledger_data: &[u8],
        sibling_ledger_data: &[u8],
    ) -> Result<u128, ProgramError> {
        let own = lp_vault_domain_nav_atoms(
            group, market_group, authority, domain, fee_share_bps, own_ledger_data,
        )?;
        let sib = lp_vault_domain_nav_atoms(
            group,
            market_group,
            authority,
            sibling_domain(domain),
            fee_share_bps,
            sibling_ledger_data,
        )?;
        own.checked_add(sib)
            .ok_or_else(|| PercolatorError::EngineArithmeticOverflow.into())
    }

    fn read_or_new_backing_domain_ledger(
        data: &[u8],
        market_group: [u8; 32],
        authority: [u8; 32],
        domain: u16,
        bucket: &percolator::BackingBucketV16,
    ) -> Result<(state::BackingDomainLedgerAccountV16, bool), ProgramError> {
        if state::is_initialized(data) {
            let ledger = state::read_backing_domain_ledger(data)?;
            if ledger.market_group != market_group
                || ledger.authority != authority
                || ledger.domain != domain
            {
                return Err(PercolatorError::Unauthorized.into());
            }
            Ok((ledger, true))
        } else {
            Ok((
                state::BackingDomainLedgerAccountV16 {
                    market_group,
                    authority,
                    total_principal_atoms: 0,
                    total_deposited_atoms: 0,
                    total_principal_withdrawn_atoms: 0,
                    total_earnings_atoms: 0,
                    total_earnings_withdrawn_atoms: 0,
                    last_observed_bucket_earnings_atoms: bucket.utilization_fee_earnings,
                    cumulative_loss_atoms: 0,
                    cumulative_recovery_atoms: 0,
                    last_observed_unavailable_principal_atoms: backing_unavailable_principal_atoms(
                        bucket,
                    )?,
                    domain,
                    _padding: [0u8; 14],
                },
                false,
            ))
        }
    }

    fn write_or_init_backing_domain_ledger(
        data: &mut [u8],
        ledger: &state::BackingDomainLedgerAccountV16,
        initialized: bool,
    ) -> ProgramResult {
        if initialized {
            state::write_backing_domain_ledger(data, ledger)
        } else {
            state::init_backing_domain_ledger(data, ledger)
        }
    }

    fn read_or_new_insurance_ledger(
        data: &[u8],
        market_group: [u8; 32],
        authority: [u8; 32],
        insurance_atoms: u128,
    ) -> Result<(state::InsuranceLedgerAccountV16, bool), ProgramError> {
        if state::is_initialized(data) {
            let ledger = state::read_insurance_ledger(data)?;
            if ledger.market_group != market_group || ledger.authority != authority {
                return Err(PercolatorError::Unauthorized.into());
            }
            Ok((ledger, true))
        } else {
            Ok((
                state::InsuranceLedgerAccountV16 {
                    market_group,
                    authority,
                    total_principal_atoms: 0,
                    total_deposited_atoms: 0,
                    total_withdrawn_atoms: 0,
                    cumulative_profit_atoms: 0,
                    cumulative_loss_atoms: 0,
                    last_observed_insurance_atoms: insurance_atoms,
                },
                false,
            ))
        }
    }

    fn write_or_init_insurance_ledger(
        data: &mut [u8],
        ledger: &state::InsuranceLedgerAccountV16,
        initialized: bool,
    ) -> ProgramResult {
        if initialized {
            state::write_insurance_ledger(data, ledger)
        } else {
            state::init_insurance_ledger(data, ledger)
        }
    }

    const DOMAIN_WITHDRAW_AUTH_INSURANCE: u8 = 0;
    const DOMAIN_WITHDRAW_AUTH_BACKING: u8 = 1;

    #[inline(never)]
    fn verify_domain_withdrawal_preflight<'a>(
        program_id: &Pubkey,
        market_ai: &AccountInfo<'a>,
        authority: &AccountInfo<'a>,
        dest_token: &AccountInfo<'a>,
        vault_token: &AccountInfo<'a>,
        vault_authority_ai: &AccountInfo<'a>,
        domain: usize,
        amount: u128,
        require_live_mode: bool,
        authority_kind: u8,
    ) -> Result<(u8, u64), ProgramError> {
        let market_data = market_ai.try_borrow_data()?;
        let (cfg, mode, configured_slots, _) =
            state::read_market_config_mode_and_capacity(&market_data)?;
        let asset_index = domain / 2;
        if (require_live_mode && mode != MarketModeV16::Live)
            || domain >= configured_slots.saturating_mul(2)
            || asset_index >= configured_slots
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let profile = read_oracle_profile_for_asset(&market_data, &cfg, asset_index)?;
        let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
        let local_authorized = match authority_kind {
            DOMAIN_WITHDRAW_AUTH_INSURANCE => {
                live_authority_matches(&authorities.insurance_operator, authority.key)
            }
            DOMAIN_WITHDRAW_AUTH_BACKING => {
                live_authority_matches(&authorities.backing_bucket_authority, authority.key)
            }
            _ => return Err(PercolatorError::InvalidInstruction.into()),
        };
        if !local_authorized && !live_authority_matches(&cfg.marketauth, authority.key) {
            return Err(PercolatorError::Unauthorized.into());
        }
        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        verify_withdrawable_token_accounts(
            dest_token,
            authority.key,
            vault_token,
            &vault_authority,
            &cfg,
        )?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(vault_token, amount_u64)?;
        Ok((bump, amount_u64))
    }

    #[inline(never)]
    fn handle_top_up_backing_bucket<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> ProgramResult {
        let signer = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let source_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let token_program = account(accounts, 4)?;
        // #433 route (b): the ledger is MANDATORY here, and this handler CREATES it when it
        // does not exist. Creation is the half the first fix was missing.
        //
        // Requiring the ledger on WITHDRAWAL alone (45bba89e) stranded funds: nothing
        // allocated the PDA, so it had to already exist, and only the LP-vault handlers ever
        // made one. Requiring it on the way IN, with creation, guarantees one exists by the
        // time anyone withdraws — which is what makes the withdrawal-side requirement safe
        // instead of a trap.
        //
        // Deliberately the DEPOSIT side. A caller who cannot form this instruction simply
        // does not deposit; the same mistake on the withdrawal side locks money already in.
        // Breaking deposits is recoverable, breaking withdrawals is not.
        let ledger_ai = account(accounts, 5)?;
        let system_program_ai = account(accounts, 6)?;
        expect_signer(signer)?;
        expect_writable(market_ai)?;
        expect_writable(source_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        expect_writable(ledger_ai)?;
        let (ledger_pda, ledger_bump) =
            state::derive_lp_backing_ledger(program_id, market_ai.key, domain);
        expect_key(ledger_ai, &ledger_pda)?;
        if ledger_ai.data_is_empty() {
            let domain_bytes = domain.to_le_bytes();
            let bump_bytes = [ledger_bump];
            let seeds: &[&[u8]] = &[
                crate::constants::LP_BACKING_LEDGER_SEED,
                market_ai.key.as_ref(),
                domain_bytes.as_ref(),
                bump_bytes.as_ref(),
            ];
            create_pda_account(
                signer,
                ledger_ai,
                system_program_ai,
                state::backing_domain_ledger_account_len(),
                program_id,
                seeds,
            )?;
        }
        expect_owner(ledger_ai, program_id)?;
        verify_token_program(token_program)?;
        let domain_usize = domain as usize;
        let (cfg_pre, authorities) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, group) = state::market_view_mut(&mut market_data)?;
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            let asset_index = domain_usize / 2;
            if group.header.mode != 0
                || domain_usize >= configured_slots.saturating_mul(2)
                || asset_index >= configured_slots
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_domain_accepts_live_topup_view(&group, domain_usize)?;
            let profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
            (cfg, authorities)
        };
        expect_live_authority(&authorities.backing_bucket_authority, signer.key)?;
        let mint = primary_collateral_mint(&cfg_pre);
        let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
        verify_user_token_account(source_token, signer.key, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(source_token, amount_u64)?;
        if amount != 0 {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            require_domain_accepts_live_topup_view(&group, domain_usize)?;
            let authorities = domain_authorities_from_view(&group, &cfg, domain_usize)?;
            expect_live_authority(&authorities.backing_bucket_authority, signer.key)?;
            let mut ledger_data = Some(ledger_ai.try_borrow_mut_data()?);
            let mut ledger_state = if let Some(data) = ledger_data.as_deref() {
                let (_, bucket) = backing_domain_parts_view(&group, domain as usize)?;
                let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                    data,
                    market_ai.key.to_bytes(),
                    authorities.backing_bucket_authority,
                    domain,
                    &bucket,
                )?;
                sync_backing_domain_ledger(&mut ledger, &bucket)?;
                Some((ledger, initialized))
            } else {
                None
            };
            group
                .deposit_fresh_counterparty_backing_not_atomic(domain_usize, amount, expiry_slot)
                .map_err(map_v16_error)?;
            if let Some((ledger, _)) = ledger_state.as_mut() {
                ledger.total_principal_atoms = ledger
                    .total_principal_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.total_deposited_atoms = ledger
                    .total_deposited_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            }
            group.validate_shape().map_err(map_v16_error)?;
            if let (Some(data), Some((ledger, initialized))) =
                (ledger_data.as_deref_mut(), ledger_state.as_ref())
            {
                write_or_init_backing_domain_ledger(data, ledger, *initialized)?;
            }
        }
        transfer_tokens(token_program, source_token, vault_token, signer, amount_u64)?;
        Ok(())
    }

    /// ExpireBackingBucket (tag 89) — see `Instruction::ExpireBackingBucket`
    /// for the full rationale. Permissionless liveness repair: advances a
    /// `Fresh`-but-LAPSED source-domain backing bucket to `Expired`/`Impaired`
    /// so settlement against that domain can proceed again.
    ///
    /// Moves no tokens. The only state transition is the engine's own
    /// `expire_source_backing_bucket_not_atomic`, which fails closed with
    /// `Stale` unless the bucket is `Fresh` and `now_slot >= expiry_slot`.
    #[inline(never)]
    fn handle_expire_backing_bucket<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
    ) -> ProgramResult {
        let market_ai = account(accounts, 0)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;

        let domain_usize = domain as usize;
        let cfg_after = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            // Live-only. A resolved/wound-down market already reaches the
            // transition through the engine's own resolved-close sweep
            // (`realize_source_backed_claims_for_resolved_close_not_atomic`),
            // so re-entering it from outside would be a second, unsequenced
            // mutation of a terminal ledger.
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            if domain_usize >= configured_slots.saturating_mul(2) {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            // The slot is the runtime Clock, NEVER a caller argument: this is
            // the only thing standing between "recover a bricked domain" and
            // "let anyone forfeit live backing early". `max` against the
            // engine's own `current_slot` keeps the two monotone, matching every
            // other authenticated-slot site in this program.
            let now_slot = authenticated_market_slot_or_fallback_view(&group);
            group
                .expire_source_backing_bucket_not_atomic(domain_usize, now_slot)
                .map_err(map_v16_error)?;
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_withdraw_backing_bucket<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let dest_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let vault_authority_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        // ⚠️ OPTIONAL, and it MUST stay optional. #433 asked for it to be mandatory and a
        // first fix (45bba89e) made it so; that was DEPLOYED and immediately stranded funds.
        //
        // The backing-domain ledger PDA is only ever ALLOCATED by the LP-vault handlers.
        // `write_or_init_backing_domain_ledger` writes into an existing buffer — nothing on
        // this path can create the account. So on any market without an LP vault the ledger
        // does not exist, `expect_owner(ledger_ai, program_id)` fails, and backing deposited
        // through the 5-account `TopUpBackingBucket` could never be withdrawn again. That is
        // strictly worse than the accounting bypass #433 reports.
        //
        // Upstream keeps it optional too (`upstream/main` handle_withdraw_backing_bucket,
        // `accounts.get(6)` + `if let Some`), which is corroboration rather than coincidence.
        //
        // #433 IS REAL and is still open: when the account is omitted, both the
        // principal-consistency guard and the decrement are skipped. Closing it needs the
        // ledger to be creatable on this path (payer + system program) or mandatory on
        // TopUpBackingBucket first — not a bare `account(accounts, 6)?`.
        // MANDATORY again, and now safe: `handle_top_up_backing_bucket` CREATES this PDA, so
        // one exists before any withdrawal is possible. Requiring it WITHOUT that creation
        // path (45bba89e) is what stranded funds — see the revert note in git history.
        let ledger_ai = account(accounts, 6)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        expect_writable(ledger_ai)?;
        expect_owner(ledger_ai, program_id)?;
        let (ledger_pda, _) = state::derive_lp_backing_ledger(program_id, market_ai.key, domain);
        expect_key(ledger_ai, &ledger_pda)?;
        verify_token_program(token_program)?;
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let domain_usize = domain as usize;
        let (bump, amount_u64) = verify_domain_withdrawal_preflight(
            program_id,
            market_ai,
            authority,
            dest_token,
            vault_token,
            vault_authority_ai,
            domain_usize,
            amount,
            false,
            DOMAIN_WITHDRAW_AUTH_BACKING,
        )?;

        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let authorities = domain_authorities_from_view(&group, &cfg, domain_usize)?;
            let shutdown_drain = match group.header.mode {
                0 => live_domain_withdraw_health_or_shutdown_view(&cfg, &group, domain_usize)?,
                1 => {
                    if group.header.materialized_portfolio_count.get() != 0
                        || group.header.c_tot.get() != 0
                    {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                    false
                }
                _ => return Err(PercolatorError::EngineLockActive.into()),
            };
            let local_authorized =
                live_authority_matches(&authorities.backing_bucket_authority, authority.key);
            let admin_shutdown_authorized =
                shutdown_drain && live_authority_matches(&cfg.marketauth, authority.key);
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            // F-3 / D-STAKE-1 guard: when backing_bucket_authority is a bound (non-zero) authority
            // — which it always is for an activated asset, and which the stake program can set to
            // its PDA — the admin shutdown-drain path MUST NOT bypass it. Mirrors the guard in
            // handle_withdraw_insurance_asset. When that authority == marketauth the local path
            // already covers a legitimate marketauth withdrawal; when it is a distinct stake PDA,
            // marketauth can no longer use shutdown-drain to bypass stake governance.
            let admin_shutdown_authorized = if authorities.backing_bucket_authority != [0u8; 32] {
                false
            } else {
                admin_shutdown_authorized
            };
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            let ledger_authority = if admin_shutdown_authorized && !local_authorized {
                cfg.marketauth
            } else {
                authorities.backing_bucket_authority
            };

            let (_, bucket) = backing_domain_parts_view(&group, domain_usize)?;
            {
                let mut ledger_data = ledger_ai.try_borrow_mut_data()?;
                let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                    &ledger_data,
                    market_ai.key.to_bytes(),
                    ledger_authority,
                    domain,
                    &bucket,
                )?;
                sync_backing_domain_ledger(&mut ledger, &bucket)?;
                if amount > ledger.total_principal_atoms {
                    return Err(PercolatorError::EngineCounterUnderflow.into());
                }
                group
                    .withdraw_fresh_counterparty_backing_not_atomic(domain_usize, amount)
                    .map_err(map_v16_error)?;
                ledger.total_principal_atoms = ledger
                    .total_principal_atoms
                    .checked_sub(amount)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                ledger.total_principal_withdrawn_atoms = ledger
                    .total_principal_withdrawn_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                group.validate_shape().map_err(map_v16_error)?;
                write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)?;
            }
        }

        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )?;
        Ok(())
    }

    #[inline(never)]
    fn handle_withdraw_backing_bucket_earnings<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let ledger_ai = account(accounts, 2)?;
        let dest_token = account(accounts, 3)?;
        let vault_token = account(accounts, 4)?;
        let vault_authority_ai = account(accounts, 5)?;
        let token_program = account(accounts, 6)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(ledger_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(ledger_ai, program_id)?;
        verify_token_program(token_program)?;
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let domain_usize = domain as usize;
        let (bump, amount_u64) = verify_domain_withdrawal_preflight(
            program_id,
            market_ai,
            authority,
            dest_token,
            vault_token,
            vault_authority_ai,
            domain_usize,
            amount,
            false,
            DOMAIN_WITHDRAW_AUTH_BACKING,
        )?;

        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let authorities = domain_authorities_from_view(&group, &cfg, domain_usize)?;
            let shutdown_drain = match group.header.mode {
                0 => live_domain_withdraw_health_or_shutdown_view(&cfg, &group, domain_usize)?,
                1 => {
                    if group.header.materialized_portfolio_count.get() != 0
                        || group.header.c_tot.get() != 0
                    {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                    false
                }
                _ => return Err(PercolatorError::EngineLockActive.into()),
            };
            let local_authorized =
                live_authority_matches(&authorities.backing_bucket_authority, authority.key);
            let admin_shutdown_authorized =
                shutdown_drain && live_authority_matches(&cfg.marketauth, authority.key);
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            // F-3 / D-STAKE-1 guard: when backing_bucket_authority is a bound (non-zero) authority
            // — which it always is for an activated asset, and which the stake program can set to
            // its PDA — the admin shutdown-drain path MUST NOT bypass it. Mirrors the guard in
            // handle_withdraw_insurance_asset. When that authority == marketauth the local path
            // already covers a legitimate marketauth withdrawal; when it is a distinct stake PDA,
            // marketauth can no longer use shutdown-drain to bypass stake governance.
            let admin_shutdown_authorized = if authorities.backing_bucket_authority != [0u8; 32] {
                false
            } else {
                admin_shutdown_authorized
            };
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            let ledger_authority = if admin_shutdown_authorized && !local_authorized {
                cfg.marketauth
            } else {
                authorities.backing_bucket_authority
            };

            let (_, bucket) = backing_domain_parts_view(&group, domain_usize)?;
            if amount > bucket.utilization_fee_earnings || amount > group.header.vault.get() {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let mut ledger_data = ledger_ai.try_borrow_mut_data()?;
            let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                &ledger_data,
                market_ai.key.to_bytes(),
                ledger_authority,
                domain,
                &bucket,
            )?;
            sync_backing_domain_ledger(&mut ledger, &bucket)?;
            group
                .withdraw_backing_provider_earnings_not_atomic(domain_usize, amount)
                .map_err(map_v16_error)?;
            ledger.last_observed_bucket_earnings_atoms = ledger
                .last_observed_bucket_earnings_atoms
                .checked_sub(amount)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            ledger.total_earnings_withdrawn_atoms = ledger
                .total_earnings_withdrawn_atoms
                .checked_add(amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            group.validate_shape().map_err(map_v16_error)?;
            write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)?;
        }

        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )?;
        Ok(())
    }

    #[inline(never)]
    fn handle_sync_backing_domain_ledger<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let ledger_ai = account(accounts, 2)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(ledger_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(ledger_ai, program_id)?;

        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, group) = state::market_view_mut(&mut market_data)?;
        let domain_usize = domain as usize;
        let authorities = domain_authorities_from_view(&group, &cfg, domain_usize)?;
        expect_live_authority(&authorities.backing_bucket_authority, authority.key)?;
        let (_, bucket) = backing_domain_parts_view(&group, domain_usize)?;
        let mut ledger_data = ledger_ai.try_borrow_mut_data()?;
        let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
            &ledger_data,
            market_ai.key.to_bytes(),
            authorities.backing_bucket_authority,
            domain,
            &bucket,
        )?;
        sync_backing_domain_ledger(&mut ledger, &bucket)?;
        write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)
    }

    #[inline(never)]
    fn handle_sync_insurance_ledger<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let ledger_ai = account(accounts, 2)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(ledger_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(ledger_ai, program_id)?;

        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, group) = state::market_view_mut(&mut market_data)?;
        let asset0_insurance_authority =
            domain_authorities_from_view(&group, &cfg, 0)?.insurance_authority;
        expect_live_authority(&asset0_insurance_authority, authority.key)?;
        let mut ledger_data = ledger_ai.try_borrow_mut_data()?;
        let observed = market_insurance_remaining_view(&group, 0)?;
        let (mut ledger, initialized) = read_or_new_insurance_ledger(
            &ledger_data,
            market_ai.key.to_bytes(),
            asset0_insurance_authority,
            observed,
        )?;
        sync_insurance_ledger(&mut ledger, observed)?;
        write_or_init_insurance_ledger(&mut ledger_data, &ledger, initialized)
    }

    #[inline(never)]
    fn handle_withdraw_insurance<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let dest_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let vault_authority_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        let ledger_ai = accounts.get(6);
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        if let Some(ledger_ai) = ledger_ai {
            expect_writable(ledger_ai)?;
            expect_owner(ledger_ai, program_id)?;
        }
        verify_token_program(token_program)?;
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // F-1: read the authenticated slot up front; fail closed if the clock syscall fails.
        let now_slot = Clock::get()?.slot;

        let (cfg_pre, policy_dirty) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let available_insurance = terminal_insurance_withdraw_capacity_for_authority_view(
                &group,
                &cfg,
                authority.key,
            )?;
            if group.header.mode != 1
                || group.header.materialized_portfolio_count.get() != 0
                || group.header.c_tot.get() != 0
                || amount > available_insurance
                || amount > group.header.vault.get()
            {
                return Err(PercolatorError::EngineLockActive.into());
            }

            // F-1: gate the withdrawal against the insurance-withdrawal cooldown before mutating
            // any state. Pure helper (unit-tested + Kani-proven). The deposits-only ceiling (F-2)
            // is enforced together with its decrement at the end of this block.
            check_insurance_withdraw_cooldown(
                cfg.insurance_withdraw_cooldown_slots,
                cfg.last_insurance_withdraw_slot,
                now_slot,
            )?;
            let mut ledger_data = if let Some(ledger_ai) = ledger_ai {
                Some(ledger_ai.try_borrow_mut_data()?)
            } else {
                None
            };
            let mut ledger_state = if let Some(data) = ledger_data.as_deref() {
                let (mut ledger, initialized) = read_or_new_insurance_ledger(
                    data,
                    market_ai.key.to_bytes(),
                    authority.key.to_bytes(),
                    available_insurance,
                )?;
                sync_insurance_ledger(&mut ledger, available_insurance)?;
                Some((ledger, initialized))
            } else {
                None
            };
            // insurance + vault + per-domain budget all decremented atomically inside the engine
            // withdraw (called per domain by the helper); no separate header decrement here.
            debit_terminal_insurance_budgets_for_authority_view(
                &mut group,
                &cfg,
                authority.key,
                amount,
            )?;
            if let Some((ledger, _)) = ledger_state.as_mut() {
                ledger.total_withdrawn_atoms = ledger
                    .total_withdrawn_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.total_principal_atoms = ledger.total_principal_atoms.saturating_sub(amount);
                ledger.last_observed_insurance_atoms = ledger
                    .last_observed_insurance_atoms
                    .checked_sub(amount)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
            }
            group.validate_shape().map_err(map_v16_error)?;
            if let (Some(data), Some((ledger, initialized))) =
                (ledger_data.as_deref_mut(), ledger_state.as_ref())
            {
                write_or_init_insurance_ledger(data, ledger, *initialized)?;
            }

            // F-1 / F-2: apply BOTH policy mutations to the single cfg binding before it leaves
            // the borrow scope, then persist once below. Mutating one binding (rather than two
            // separate write-backs) prevents dropping the cooldown update when the deposits-only
            // ceiling is also active, and vice-versa.
            // F-1 / F-2: apply both policy mutations to the single cfg binding before it leaves the
            // borrow scope (one binding, so neither update can clobber the other — this is the
            // co-activation bug the original PR #389 had), then persist once below.
            // apply_insurance_withdraw_ceiling enforces the deposits-only ceiling and returns the
            // decremented remaining (or the unchanged value when the ceiling is disabled).
            let policy_dirty = cfg.insurance_withdraw_cooldown_slots > 0
                || cfg.insurance_withdraw_deposits_only != 0;
            if cfg.insurance_withdraw_cooldown_slots > 0 {
                cfg.last_insurance_withdraw_slot = now_slot;
            }
            cfg.insurance_withdraw_deposit_remaining = apply_insurance_withdraw_ceiling(
                cfg.insurance_withdraw_deposits_only,
                cfg.insurance_withdraw_deposit_remaining,
                amount,
            )?;
            (cfg, policy_dirty)
        };

        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        verify_withdrawable_token_accounts(
            dest_token,
            authority.key,
            vault_token,
            &vault_authority,
            &cfg_pre,
        )?;

        // F-1 / F-2: persist the policy update (cooldown slot + deposits-only ceiling decrement).
        // Skipped when no insurance-withdrawal policy is configured, preserving exact prior
        // behavior for markets without the policy.
        if policy_dirty {
            state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_pre)?;
        }
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(vault_token, amount_u64)?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )?;
        Ok(())
    }

    #[inline(never)]
    fn handle_withdraw_insurance_asset<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        amount: u128,
    ) -> ProgramResult {
        let operator = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let dest_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let vault_authority_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        let ledger_ai = accounts.get(6);
        expect_signer(operator)?;
        expect_writable(market_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        if let Some(ledger_ai) = ledger_ai {
            expect_writable(ledger_ai)?;
            expect_owner(ledger_ai, program_id)?;
        }
        verify_token_program(token_program)?;
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // #396: the insurance-withdrawal cooldown is market-wide — enforce it on this
        // per-asset path too. Read the slot up front; fail closed if the clock syscall fails.
        let now_slot = Clock::get()?.slot;
        let asset_index = asset_index as usize;
        let long_domain = asset_index
            .checked_mul(2)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let (bump, amount_u64) = verify_domain_withdrawal_preflight(
            program_id,
            market_ai,
            operator,
            dest_token,
            vault_token,
            vault_authority_ai,
            long_domain,
            amount,
            true,
            DOMAIN_WITHDRAW_AUTH_INSURANCE,
        )?;
        let (cfg_after, cooldown_dirty) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            if asset_index >= configured_slots || asset_index >= group.markets.len() {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let shutdown_drain =
                live_domain_withdraw_health_or_shutdown_view(&cfg, &group, long_domain)?;
            let authorities = domain_authorities_from_view(&group, &cfg, long_domain)?;
            let local_authorized =
                live_authority_matches(&authorities.insurance_operator, operator.key);
            let admin_shutdown_authorized = asset_index != 0
                && shutdown_drain
                && live_authority_matches(&cfg.marketauth, operator.key);
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            // D-STAKE-1 guard: when insurance_authority is a bound (non-zero) PDA —
            // which the stake program sets via BindInsuranceAuthority — the admin
            // shutdown-drain path MUST NOT be used to bypass stake-program governance.
            // Stakers are entitled to a ReturnInsurance CPI from the stake program;
            // allowing marketauth to drain directly undermines that guarantee.
            // If insurance_authority is set, only the local insurance_operator path
            // is valid (admin_shutdown_authorized is silently overridden to false).
            let admin_shutdown_authorized = if authorities.insurance_authority != [0u8; 32] {
                // Bound PDA detected — admin shutdown drain not permitted.
                false
            } else {
                admin_shutdown_authorized
            };
            if !local_authorized && !admin_shutdown_authorized {
                return Err(PercolatorError::Unauthorized.into());
            }
            // #396: enforce the market-wide insurance-withdrawal cooldown on this per-asset path
            // too — it shares insurance_withdraw_cooldown_slots / last_insurance_withdraw_slot with
            // the terminal handle_withdraw_insurance. (The deposits-only ceiling stays terminal-only;
            // its budget tracks market-zero deposited principal, not per-asset insurance.)
            check_insurance_withdraw_cooldown(
                cfg.insurance_withdraw_cooldown_slots,
                cfg.last_insurance_withdraw_slot,
                now_slot,
            )?;
            // The ledger is an operator-held receipt: its authority must equal the executing
            // signer so that a ledger belonging to the insurance_authority cannot be co-opted
            // as a withdrawal receipt for the operator (or vice-versa).  In the admin-shutdown
            // fallback path the marketauth is the executing signer; in the normal path the
            // insurance_operator is.
            let ledger_authority = if admin_shutdown_authorized && !local_authorized {
                cfg.marketauth
            } else {
                operator.key.to_bytes()
            };
            let available = market_insurance_withdraw_capacity_view(&group, asset_index)?;
            if amount > available
                || amount > group.header.insurance.get()
                || amount > group.header.vault.get()
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let mut ledger_data = if let Some(ledger_ai) = ledger_ai {
                Some(ledger_ai.try_borrow_mut_data()?)
            } else {
                None
            };
            let mut ledger_state = if let Some(data) = ledger_data.as_deref() {
                let (mut ledger, initialized) = read_or_new_insurance_ledger(
                    data,
                    market_ai.key.to_bytes(),
                    ledger_authority,
                    available,
                )?;
                sync_insurance_ledger(&mut ledger, available)?;
                Some((ledger, initialized))
            } else {
                None
            };
            // Atomic insurance/vault/budget withdraw through the engine (maintains the
            // insurance_domain_budget_remaining_total aggregate).
            debit_market_insurance_budget_view(&mut group, asset_index, amount)?;
            if let Some((ledger, _)) = ledger_state.as_mut() {
                ledger.total_withdrawn_atoms = ledger
                    .total_withdrawn_atoms
                    .checked_add(amount)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                ledger.total_principal_atoms = ledger.total_principal_atoms.saturating_sub(amount);
                ledger.last_observed_insurance_atoms = ledger
                    .last_observed_insurance_atoms
                    .checked_sub(amount)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
            }
            group.validate_shape().map_err(map_v16_error)?;
            if let (Some(data), Some((ledger, initialized))) =
                (ledger_data.as_deref_mut(), ledger_state.as_ref())
            {
                write_or_init_insurance_ledger(data, ledger, *initialized)?;
            }
            // #396: record this withdrawal against the market-wide cooldown clock (shared with
            // the terminal path), applied to a single cfg binding then persisted once below.
            let cooldown_dirty = cfg.insurance_withdraw_cooldown_slots > 0;
            if cooldown_dirty {
                cfg.last_insurance_withdraw_slot = now_slot;
            }
            (cfg, cooldown_dirty)
        };
        // #396: persist the cooldown-slot update (only when a cooldown is configured, so markets
        // without the policy keep their exact prior behavior / no extra write).
        if cooldown_dirty {
            state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        }
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )?;
        Ok(())
    }

    /// WithdrawProtocolFee (tag 84, design §3.1). Pays out from the accrued-
    /// but-unwithdrawn protocol claim to an external token account.
    /// `amount == 0` means "withdraw all currently-available capacity".
    /// Modeled on `handle_withdraw_insurance_asset` minus the domain-budget
    /// bookkeeping (and with no insurance-withdraw-cooldown gate: that
    /// mechanism is a creator-facing anti-drain throttle on the *domain*
    /// budgets; the protocol's claim is a separately-accounted, non-domain
    /// balance and `protocol_fee_authority` is not an adversary this design
    /// defends against).
    ///
    /// W12: ResolveMarket is one-way (no path back to Live), so a Live-only
    /// gate here would permanently strand any outstanding
    /// `protocol_fee_accrued_atoms` backlog the instant a market resolves --
    /// forever, since there is no other exit for it. Mirrors
    /// `handle_withdraw_insurance`'s (tag 41) bounded terminal exit: Resolved
    /// is allowed once the market is fully wound down
    /// (`materialized_portfolio_count == 0 && c_tot == 0`, i.e. every
    /// portfolio has closed with no unfinalized resolved-payout receipt and
    /// no outstanding capital claim -- see
    /// `is_empty_for_dematerialization`/`deregister_empty_materialized_portfolio_not_atomic`
    /// in the engine). At that point `vault` has no other claimant, so the
    /// existing `engine_available`/`vault` clamp below is exactly as safe as
    /// it is in Live mode -- this does not weaken the reserve invariant, it
    /// only widens *when* the already-bounded surplus withdraw is reachable.
    #[inline(never)]
    fn handle_withdraw_protocol_fee<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let dest_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let vault_authority_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;

        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;

        let (transfer_amount_u64, cfg_after) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let live_mode = group.header.mode == 0;
            let resolved_mode = group.header.mode == 1;
            if !live_mode && !resolved_mode {
                return Err(PercolatorError::EngineLockActive.into());
            }
            if resolved_mode
                && (group.header.materialized_portfolio_count.get() != 0
                    || group.header.c_tot.get() != 0)
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            if !live_authority_matches(&cfg.protocol_fee_authority, authority.key) {
                return Err(PercolatorError::Unauthorized.into());
            }
            verify_withdrawable_token_accounts(
                dest_token,
                authority.key,
                vault_token,
                &vault_authority,
                &cfg,
            )?;
            // §1.3/N2 clamp: crank rewards (`credit_account_from_insurance_not_atomic`
            // callers) used to share the same unbudgeted-surplus gap the
            // protocol's claim lives in -- since the RESERVE amendment
            // (~/v17/DECISIONS-LEDGER.md) they are excluded from it via
            // `additional_reserved`, but this clamp is kept as defense in
            // depth: `protocol_fee_accrued_atoms - protocol_fee_withdrawn_atoms`
            // is still a wrapper-side ledger that could in principle race
            // ahead of what's actually on-chain (e.g. multiple markets
            // sharing one mint's accounting quirks), so the transfer is
            // clamped to what's actually available and only the ACTUALLY
            // transferred amount is marked withdrawn (a partial fill),
            // rather than erroring the whole instruction. See
            // `protocol_fee_withdraw_amount`'s doc comment for the pure,
            // Kani-proved core of this bound
            // (`kani_protocol_claim_never_exceeds_accrued`, §5.2).
            let engine_available = group
                .header
                .insurance
                .get()
                .saturating_sub(group.header.source_insurance_credit_reserved_total_atoms.get())
                .saturating_sub(group.header.insurance_domain_budget_remaining_total.get());
            let (transfer_amount, next_withdrawn) = protocol_fee_withdraw_amount(
                cfg.protocol_fee_accrued_atoms,
                cfg.protocol_fee_withdrawn_atoms,
                amount,
                engine_available,
                group.header.vault.get(),
            )?;
            let transfer_amount_u64 = amount_to_u64(transfer_amount)?;
            require_token_balance(vault_token, transfer_amount_u64)?;
            group
                .withdraw_insurance_surplus_not_atomic(transfer_amount)
                .map_err(map_v16_error)?;
            cfg.protocol_fee_withdrawn_atoms = next_withdrawn;
            group.validate_shape().map_err(map_v16_error)?;
            (transfer_amount_u64, cfg)
        };
        // Unconditional write-back: every successful call here mutates
        // protocol_fee_withdrawn_atoms, unlike the trade-credit sites' opt-in
        // cfg_after pattern.
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            transfer_amount_u64,
            signer_seeds,
        )
    }

    /// WithdrawCreatorFee (tag 90, creator-fee-claim design §3). Pays the
    /// creator's accrued trade-fee share out of the vault and debits
    /// `cfg.creator_fee_claimable_atoms` by exactly `amount`.
    ///
    /// Modeled on `handle_withdraw_protocol_fee` (tag 84) — same six accounts,
    /// same derived-vault-authority transfer, same mode gate — with three
    /// deliberate divergences:
    ///
    /// 1. AUTHORITY is asset 0's `asset_admin`, and ONLY that. It bootstraps to
    ///    the asset activator (the creator) at `InitMarket` / activation, and is
    ///    rotated ONLY by its holder via `UpdateAssetAuthority` self-rotation.
    ///    The one path that can rewrite it on an EXISTING slot is the
    ///    re-activation branch of `handle_update_asset_lifecycle` (reachable by
    ///    `marketauth`), which is barred from asset 0 (it rejects the in-service
    ///    lifecycles, `ASSET_ACTION_RETIRE` rejects `asset_index == 0` so asset 0
    ///    can never be RETIRED/re-activated, and an explicit `asset_index == 0`
    ///    guard pins that). So `asset_admin` for asset 0 is stable creator-only.
    ///
    ///    WHY `asset_admin` AND NOT `insurance_operator`: the wizard's full
    ///    create flow runs `StakeInitPool` + `BindInsuranceAuthority`, which
    ///    rotate `marketauth`, `insurance_authority` AND `insurance_operator` to
    ///    program PDAs (the stake pool / vault_auth). Gating this claim on any of
    ///    those makes the creator's own fees UNCLAIMABLE on a staked market — no
    ///    wallet holds a PDA's key. Verified on the live staked market
    ///    `7FBXdrm1…`: `insurance_operator` was a PDA while `asset_admin` was the
    ///    creator's wallet. `asset_admin` is the one creator-facing field the
    ///    stake flow leaves alone. This is also why `verify_domain_withdrawal_
    ///    preflight` is NOT reused: it accepts `cfg.marketauth` as an alternate
    ///    gate, and on a staked market that IS the stake-pool PDA — that path
    ///    would hand the creator's revenue to the pool.
    ///
    /// 2. NO health-check / cooldown, unlike tag 57 `WithdrawInsuranceAsset`.
    ///    Those gates exist because tag 57 draws down the per-domain insurance
    ///    budget, which IS the loss backstop
    ///    (`consume_domain_insurance_for_negative_pnl`). This counter is
    ///    disjoint from that budget by construction — the creator leg no longer
    ///    touches any domain budget — so backstop-health gating has nothing to
    ///    protect here.
    ///
    /// 3. EXACT DEBIT, NO PARTIAL FILL. `amount` must be nonzero and
    ///    `<= creator_fee_claimable_atoms`; over-claims are rejected rather
    ///    than saturated. If the shared unbudgeted surplus is momentarily too
    ///    thin (the protocol/LP/stake legs draw from the same pool),
    ///    `withdraw_insurance_surplus_not_atomic` fails closed with
    ///    `EngineLockActive` and NOTHING is debited — the claim stays fully
    ///    claimable and the creator retries with a smaller amount. Tags 84/87
    ///    clamp-and-partial-fill instead; that is incompatible with an exact
    ///    single-counter debit, and unlike them this leg has no
    ///    `accrued`/`withdrawn` pair that a partial fill could reconcile
    ///    against.
    ///
    /// MODE GATE mirrors tag 84's (Live, or Resolved once fully wound down),
    /// and for the same W12 reason: `ResolveMarket` is one-way and tag 90 is
    /// this counter's ONLY exit, so a Live-only gate would strand every
    /// unclaimed creator atom permanently the instant a market resolves.
    #[inline(never)]
    fn handle_withdraw_creator_fee<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let dest_token = account(accounts, 2)?;
        let vault_token = account(accounts, 3)?;
        let vault_authority_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_writable(dest_token)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;

        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;

        let (transfer_amount_u64, cfg_after) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let live_mode = group.header.mode == 0;
            let resolved_mode = group.header.mode == 1;
            if !live_mode && !resolved_mode {
                return Err(PercolatorError::EngineLockActive.into());
            }
            if resolved_mode
                && (group.header.materialized_portfolio_count.get() != 0
                    || group.header.c_tot.get() != 0)
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            // Authority: asset 0's `asset_admin` ONLY. `live_authority_matches`
            // also rejects the all-zero key, so a burned/unconfigured admin can
            // never be claimed against by a zero-key signer.
            //
            // Why `asset_admin` and NOT `insurance_operator`: the wizard's full
            // create flow runs `StakeInitPool` + `BindInsuranceAuthority`, which
            // rotate `marketauth`, `insurance_authority` AND `insurance_operator`
            // to program PDAs (the stake pool / vault_auth). Gating on any of
            // those would make the creator's own fees unclaimable on a staked
            // market -- no wallet holds a PDA's key. Verified on a live staked
            // market (7FBXdrm1…): insurance_operator was a PDA while `asset_admin`
            // remained the creator's wallet. `asset_admin` bootstraps to the
            // asset activator (the creator) and is rotated ONLY by its holder via
            // `UpdateAssetAuthority` -- the stake flow never touches it. It is the
            // one field that reliably tracks the creator through staking, and it
            // already gates other creator ops (e.g. RestartAssetOracle).
            let asset0_profile = read_oracle_profile_from_view(&group, &cfg, 0)?;
            if !live_authority_matches(&asset0_profile.asset_admin, authority.key) {
                return Err(PercolatorError::Unauthorized.into());
            }
            verify_withdrawable_token_accounts(
                dest_token,
                authority.key,
                vault_token,
                &vault_authority,
                &cfg,
            )?;
            // Exact capacity check, in u128 so an `amount` above u64::MAX is an
            // over-claim (rejected) rather than a `try_from` panic-adjacent
            // edge case. Reject-not-saturate, and reject the no-op zero claim.
            if amount == 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            // A CALLER error (over-ask), not an internal-invariant violation --
            // hence its own ordinal rather than the engine's
            // `EngineCounterUnderflow`, which stays reserved for the
            // fail-closed `checked_sub` below.
            if amount > cfg.creator_fee_claimable_atoms as u128 {
                return Err(PercolatorError::CreatorFeeOverClaim.into());
            }
            let transfer_amount_u64 = amount_to_u64(amount)?;
            require_token_balance(vault_token, transfer_amount_u64)?;
            // I-a, V-a: the atoms leave both the insurance fund and the vault.
            // The creator leg was charged into `header.insurance` by the engine
            // and (since the creator-fee-claim change) was never credited to any
            // domain budget, so it is exactly the "unbudgeted surplus" this
            // primitive is bounded by. It hard-errors if another leg got there
            // first, leaving the counter untouched.
            group
                .withdraw_insurance_surplus_not_atomic(amount)
                .map_err(map_v16_error)?;
            // `checked_sub` cannot fail after the clamp above; it is kept so a
            // future edit that weakens the clamp still fails closed rather than
            // wrapping the counter to ~1.8e19 claimable atoms.
            cfg.creator_fee_claimable_atoms = cfg
                .creator_fee_claimable_atoms
                .checked_sub(amount as u64)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            group.validate_shape().map_err(map_v16_error)?;
            (transfer_amount_u64, cfg)
        };
        // Unconditional write-back, as in `handle_withdraw_protocol_fee`: every
        // successful call here debits `creator_fee_claimable_atoms` (a zero
        // amount errored above). Without it the counter resets and the SAME
        // atoms are claimable again on the next call.
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            dest_token,
            vault_authority_ai,
            transfer_amount_u64,
            signer_seeds,
        )
    }

    /// SetProtocolFeeAuthority (tag 85, design §3.2). Rotates
    /// `protocol_fee_authority` on a single market. Gated on the program's
    /// BPF upgrade authority -- NOT `marketauth`, NOT any
    /// creator/insurance_authority-facing gate. No global fan-out: a
    /// keeper script iterates markets if a mass rotation is ever needed
    /// (v2 nicety, not a blocker).
    #[inline(never)]
    fn handle_set_protocol_fee_authority<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        new_authority: [u8; 32],
    ) -> ProgramResult {
        let upgrade_authority = account(accounts, 0)?;
        let program_data_ai = account(accounts, 1)?;
        let market_ai = account(accounts, 2)?;
        expect_signer(upgrade_authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;

        let (program_data_key, _) = derive_program_data_address(program_id);
        expect_key(program_data_ai, &program_data_key)?;
        let stored_upgrade_authority = read_program_data_upgrade_authority(program_data_ai)?;
        if stored_upgrade_authority != Some(*upgrade_authority.key) {
            return Err(PercolatorError::Unauthorized.into());
        }

        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        cfg.protocol_fee_authority = new_authority;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    /// UpdateFeeSplit (tag 86) — marketauth-gated. Validates the shares, then
    /// stores them. Validation lives ONLY here, never in a load-time
    /// validator (see `policy_v16::validate_fee_split`'s doc comment).
    ///
    /// Marketauth-gated idiom mirrors the neighbouring single-field setters
    /// (`handle_update_maintenance_fee_policy`, `handle_update_fee_redirect_policy`,
    /// `handle_update_market_init_fee_policy`): signer/writable/owner checks,
    /// load cfg via `read_market_config_mode_and_capacity`, gate on
    /// `cfg.marketauth` via `expect_live_authority`, mutate, write back.
    /// (`handle_update_trade_fee_policy` gates on asset-0's insurance
    /// authority instead of `marketauth`, so it is not the pattern to mirror
    /// here despite sharing the "policy setter" name.)
    #[inline(never)]
    fn handle_update_fee_split<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        creator_share_bps: u16,
        lp_share_bps: u16,
        insurance_share_bps: u16,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        policy_v16::validate_fee_split(creator_share_bps, lp_share_bps, insurance_share_bps)?;
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.creator_share_bps = creator_share_bps;
        cfg.lp_share_bps = lp_share_bps;
        cfg.insurance_share_bps = insurance_share_bps;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    /// Reads and validates a percolator-stake `StakePool` account, returning
    /// its `vault` token-account key and its `vault_authority` PDA.
    ///
    /// EVERY value that decides where tokens land is DERIVED here, never taken
    /// from the caller. The caller supplies account handles; it does not get to
    /// choose what they are allowed to be.
    ///
    /// THE TRUST ROOT is the PINNED `constants::STAKE_PROGRAM_ID`, asserted
    /// against `pool_ai.owner` in step (1) BEFORE any byte of the account is
    /// read. Everything downstream — both PDA derivations and every field read
    /// — is anchored to that constant, never to caller-supplied data.
    ///
    /// SECURITY — the hole this closes, and why the previous mitigation did not.
    /// An earlier version recovered the stake program as `*pool_ai.owner` and
    /// then validated the pool self-consistently against it. Every check
    /// (vault_auth derivation, pool PDA, discriminator, version, slab, wrapper
    /// id, pool_mode, vault) passed — with respect to a program the ATTACKER
    /// chose. The full forgery: deploy program `X`; compute
    /// `pool = PDA(["stake_pool", market], X)` and
    /// `vault_auth = PDA(["vault_auth", pool], X)`; point asset 0's
    /// `insurance_authority` at `vault_auth`; have `X` write a
    /// `STAKE_POOL_LEN`-byte account at `pool` with the right discriminator,
    /// version, `is_initialized`, `slab == market`, `percolator_program == `
    /// this wrapper, `pool_mode == 0`, and `vault == ` a token account owned by
    /// `vault_auth`. Tag 87 then paid out to `X`'s vault. On a market with a
    /// real bound pool the creator could rotate away, crank, and rotate back,
    /// so stakers never even observed the theft.
    ///
    /// The previous mitigation — requiring asset 0's `asset_admin` to be burned
    /// — did NOT close this, and has been REMOVED. `handle_update_asset_authority`
    /// has two branches: the `admin_signed` branch, and self-rotation by the
    /// authority's CURRENT holder (`if !admin_signed { expect_live_authority(
    /// &current_value, current.key)? }`). Burning `asset_admin` kills only the
    /// first. `InitMarket` bootstraps `insurance_authority = cfg.marketauth` =
    /// the creator's own wallet, so AFTER the burn the creator is still the
    /// current holder and simply self-rotates `insurance_authority` to the
    /// forged `vault_auth`. The burn bought zero security and imposed a
    /// bind-then-burn ordering footgun (tag 87 failed closed until an operator
    /// ran a burn that was never actually load-bearing).
    ///
    /// With the owner pinned, `insurance_authority` is only a POINTER, and
    /// rotating it is harmless: to pass step (3) the rotated value must equal
    /// `PDA(["vault_auth", pool], STAKE_PROGRAM_ID)` — a PDA under a program the
    /// attacker does not control and cannot sign for. Forging that would mean
    /// finding a preimage for a chosen 32-byte PDA target, not exploiting a
    /// validation gap. So the creator may rotate `insurance_authority` freely;
    /// the only thing they can do is make tag 87 fail.
    ///
    /// (This sentence said "step (2)" until the branch-review pass. The steps
    /// were renumbered when the burn gate was removed and (0) was inserted, so
    /// it pointed at the zero-check instead of the `vault_auth` PDA equality.
    /// The step numbers below are the authority; keep them in sync with this
    /// paragraph if the sequence changes again.)
    ///
    /// This matters because tag 87 reaches a fund `WithdrawInsurance` (tag 41)
    /// cannot: tag 41 is Resolved-only and budget-scoped
    /// (`terminal_insurance_withdraw_capacity_for_authority_view`), whereas tag
    /// 87 draws the UNBUDGETED Live-mode surplus this handler's clamp isolates.
    /// Left unpinned it was a NEW extraction path that let a creator recapture
    /// the exact insurance leg the fee-split floors exist to guarantee.
    fn load_bound_stake_pool(
        program_id: &Pubkey,
        market_ai: &AccountInfo,
        pool_ai: &AccountInfo,
        bound_insurance_authority: &[u8; 32],
    ) -> Result<(Pubkey, Pubkey), ProgramError> {
        // (0) THE PIN. On a build with no pinned stake program id (i.e. any
        // non-`devnet` build — v17 percolator-stake has no mainnet deployment)
        // there is no program we are willing to send tokens to, so refuse
        // before touching anything. Fail closed: the atoms stay in
        // `header.insurance`. See `constants::STAKE_PROGRAM_ID`.
        #[cfg(not(feature = "devnet"))]
        {
            let _ = (program_id, market_ai, pool_ai, bound_insurance_authority);
            return Err(PercolatorError::StakeProgramNotPinned.into());
        }
        #[cfg(feature = "devnet")]
        {
            let stake_program = crate::constants::STAKE_PROGRAM_ID;
            // (1) OWNER PIN — FIRST, BEFORE ANY BYTE IS READ. This is the check
            // the whole handler rests on. Without it every subsequent test is
            // merely self-consistent with respect to a program the caller
            // chose, and the pool is forgeable end to end (see the SECURITY
            // block). Ordering matters: reading fields out of an account owned
            // by an unknown program and only later asking who owns it would let
            // attacker bytes influence anything that happens in between.
            if *pool_ai.owner != stake_program {
                return Err(PercolatorError::StakePoolOwnerMismatch.into());
            }
            // (2) No bound stake pool ⇒ nobody is owed this leg. NOTE: on a
            // fresh market this is `marketauth`, not zero, so this test is a
            // backstop for an explicitly-zeroed authority rather than the
            // "never bound" check it reads as. The real "never bound"
            // rejection comes from step (3): an unbound `insurance_authority`
            // is a wallet key, which is on-curve and therefore can never equal
            // a derived `vault_auth` PDA.
            if *bound_insurance_authority == [0u8; 32] {
                return Err(PercolatorError::StakePoolNotBound.into());
            }
            // (3) The bound authority must be THIS pool's `vault_auth` under
            // the PINNED program. Because the program is pinned, a creator who
            // rotates `insurance_authority` (which they can still do, via
            // self-rotation — burning `asset_admin` never prevented that) can
            // only point it at something that fails this test. They can break
            // their own payout; they cannot redirect it.
            let (vault_authority, _) = Pubkey::find_program_address(
                &[
                    crate::constants::STAKE_VAULT_AUTHORITY_SEED,
                    pool_ai.key.as_ref(),
                ],
                &stake_program,
            );
            if vault_authority.to_bytes() != *bound_insurance_authority {
                return Err(PercolatorError::StakePoolAuthorityMismatch.into());
            }
            // (4) …and it must be THE pool for THIS market, again derived under
            // the pinned program. One pool per market by construction of the
            // seed, so this is an equality test, not a search.
            let (expected_pool, _) = Pubkey::find_program_address(
                &[crate::constants::STAKE_POOL_SEED, market_ai.key.as_ref()],
                &stake_program,
            );
            expect_key(pool_ai, &expected_pool)?;

            // Only NOW is it safe to read bytes: the account is owned by the
            // pinned stake program, so its contents are that program's state,
            // not attacker-authored data.
            let data = pool_ai.try_borrow_data()?;
            if data.len() < crate::constants::STAKE_POOL_LEN {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            // (5) Discriminator + version + init flag: refuse to parse a stake
            // account of some other kind, or a layout we do not know.
            if data[crate::constants::STAKE_POOL_OFF_DISCRIMINATOR
                ..crate::constants::STAKE_POOL_OFF_DISCRIMINATOR + 8]
                != crate::constants::STAKE_POOL_DISCRIMINATOR
                || data[crate::constants::STAKE_POOL_OFF_VERSION]
                    != crate::constants::STAKE_POOL_VERSION
                || data[crate::constants::STAKE_POOL_OFF_IS_INITIALIZED] != 1
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            // (6) The pool's own record of its bindings must agree with ours.
            // Redundant with (4) for `slab` — kept because it costs nothing and
            // makes a future seed change fail closed instead of silently
            // redirecting funds.
            let mut slab = [0u8; 32];
            slab.copy_from_slice(
                &data[crate::constants::STAKE_POOL_OFF_SLAB
                    ..crate::constants::STAKE_POOL_OFF_SLAB + 32],
            );
            if slab != market_ai.key.to_bytes() {
                return Err(PercolatorError::StakePoolMarketMismatch.into());
            }
            // (7) The pool must CPI *this* wrapper deployment. A pool bound to a
            // different wrapper program is not this market's staker constituency.
            let mut cpi_target = [0u8; 32];
            cpi_target.copy_from_slice(
                &data[crate::constants::STAKE_POOL_OFF_PERCOLATOR_PROGRAM
                    ..crate::constants::STAKE_POOL_OFF_PERCOLATOR_PROGRAM + 32],
            );
            if cpi_target != program_id.to_bytes() {
                return Err(PercolatorError::StakePoolWrapperMismatch.into());
            }
            // (8) Insurance-LP mode only. That is the mode whose stakers absorb
            // this market's losses via `FlushToInsurance`; this fee leg is their
            // compensation for exactly that exposure. Paying it to a pool that
            // carries no such exposure would be an unearned transfer.
            if data[crate::constants::STAKE_POOL_OFF_MODE]
                != crate::constants::STAKE_POOL_MODE_INSURANCE_LP
            {
                return Err(PercolatorError::StakePoolModeMismatch.into());
            }
            // (9) The destination, read out of the validated pool.
            let mut vault = [0u8; 32];
            vault.copy_from_slice(
                &data[crate::constants::STAKE_POOL_OFF_VAULT
                    ..crate::constants::STAKE_POOL_OFF_VAULT + 32],
            );
            // `vault_authority` was proven equal to the bound
            // `insurance_authority` in (3); returning it lets the caller assert
            // the destination token account's SPL owner is that same PDA.
            Ok((Pubkey::new_from_array(vault), vault_authority))
        }
    }

    /// WithdrawInsuranceReserveToStake (tag 87) — permissionless.
    ///
    /// Transfers `insurance_reserve_accrued - insurance_reserve_withdrawn` out
    /// of the market vault and into the bound stake pool's vault, where
    /// percolator-stake's `AccrueFees` measures it as surplus over
    /// `total_pool_value()` and distributes it to stakers. Stakers absorb this
    /// market's losses via `FlushToInsurance`; this leg is their compensation.
    ///
    /// PERMISSIONLESS, SAFELY. The destination is not an argument and is not
    /// caller-chosen: it is `pool.vault` read out of the pool at
    /// `["stake_pool", market]` under the pinned stake program id (see
    /// `load_bound_stake_pool`). Every candidate destination a caller could
    /// substitute fails one of those checks, so there is nothing to redirect —
    /// the only thing a caller decides is *when* the push happens.
    ///
    /// MODE GATE — Live-only, matching tag 78 (the other permissionless leg)
    /// and deliberately STRICTER than `handle_withdraw_protocol_fee`'s
    /// Live-or-wound-down-Resolved gate (its `live_mode` / `resolved_mode`
    /// block).
    ///
    /// Why not the protocol-fee model. Tag 84 may run in Resolved because it is
    /// signer-gated on `protocol_fee_authority` AND because W12 applies to it:
    /// ResolveMarket is one-way, so a Live-only gate there would strand the
    /// protocol's backlog forever, as tag 84 is its ONLY exit. The first premise
    /// does not hold here — this instruction carries no authority signature at
    /// all, only `expect_signer` on an arbitrary fee payer, so allowing it in a
    /// terminal state hands a permissionless drain to anyone.
    ///
    /// ⚠ THE SECOND PREMISE DOES APPLY, AND THIS LEG IS FORFEITED BY IT. An
    /// earlier version of this comment claimed refusing on Resolved "strands
    /// nothing" because the reserve stays reclaimable by the stake program via
    /// `WithdrawInsurance` (tag 41), on the grounds that a bound
    /// `insurance_authority` IS the pool's `vault_auth` PDA. THAT IS WRONG: tag
    /// 41's capacity is budget-scoped
    /// (`terminal_insurance_withdraw_capacity_for_authority_view`), while the
    /// atoms this leg pays out are the UNBUDGETED surplus that the clamp below
    /// deliberately isolates. Tag 41 cannot reach them. `ResolveMarket` being
    /// one-way, any `insurance_reserve_accrued - withdrawn` that has not been
    /// pushed before the market resolves is PERMANENTLY UNREACHABLE by stakers.
    ///
    /// That is a real, accepted cost, not a non-issue. It is accepted because
    /// the alternative — a permissionless token-moving instruction that still
    /// runs after resolution — is worse (see the Recovery note below), and
    /// because the leg is continuously crankable by anyone for the entire Live
    /// lifetime of the market, so the forfeited amount is bounded by whatever
    /// accrues between the last successful crank and resolution. Keepers should
    /// crank tag 87 before `ResolveMarket`, not after.
    ///
    /// Concretely blocked:
    ///   * Recovery (mode 2) — the important one, and worse here than for tag
    ///     78. Post-solvency-event, `header.insurance` IS the recovery buffer,
    ///     and stakers are precisely the party contractually meant to be
    ///     FUNDING it (`FlushToInsurance` pushes stake INTO insurance). Letting
    ///     any signer run the pump backwards during a shortfall would drain the
    ///     buffer covering the loss into the pockets of the constituency whose
    ///     job is to cover it. Tag 78 at least leaves the atoms inside the
    ///     market as a junior LP claim; here they leave the program entirely as
    ///     SPL tokens and stakers can withdraw them.
    ///   * Resolved (mode 1) — same drain, before trader portfolios are
    ///     materialised. Note this is the FORFEITING case described above: there
    ///     is no tag-41 fallback for the unbudgeted leg.
    ///   * Live-but-matured — `reject_permissionless_resolve_matured_live_view`,
    ///     as tag 78 uses: no permissionless token movement out of a market
    ///     that is past its stale-resolve horizon and merely awaiting a
    ///     resolve.
    ///
    /// A rejected call never marks anything withdrawn, so `accrued - withdrawn`
    /// stays fully claimable IF the market can return to Live — true for the
    /// matured-Live and Recovery cases, and NOT true for Resolved, which is
    /// terminal and therefore forfeits the outstanding leg as described above.
    ///
    /// MANDATORY CLAMP. The protocol leg (tag 84), the LP leg (tag 78) and this
    /// stake leg ALL draw from one pool: `insurance −
    /// source_insurance_credit_reserved_total_atoms −
    /// insurance_domain_budget_remaining_total`. Nothing checks that the three
    /// wrapper-side counters sum within it, so whichever leg cranks last would
    /// get `EngineLockActive` out of the engine unless each clamps its own
    /// claim first. Mirrors `handle_withdraw_protocol_fee`'s `§1.3/N2 clamp`,
    /// then advances `insurance_reserve_withdrawn_atoms` by the amount
    /// ACTUALLY TRANSFERRED — never the pre-clamp capacity — so a partial fill
    /// leaves the remainder claimable next call instead of marking it paid
    /// without paying it.
    ///
    /// NO RESERVATION. `insurance_reserve_accrued - withdrawn` is deliberately
    /// NOT added to `additional_reserved` at the
    /// `credit_account_from_insurance_not_atomic` call sites. That was tried
    /// for the LP leg and reverted (`9a6502ae`): it makes fee claims senior to
    /// bad-debt/socialized-loss coverage, contradicting the decision that these
    /// claims are at-risk, and it reverts the whole `SyncMaintenanceFee` on
    /// distressed markets. The clamp above is what keeps this leg honest.
    #[inline(never)]
    fn handle_withdraw_insurance_reserve_to_stake<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let cranker = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let stake_pool_ai = account(accounts, 2)?;
        let stake_vault_ai = account(accounts, 3)?;
        let vault_token = account(accounts, 4)?;
        let vault_authority_ai = account(accounts, 5)?;
        let token_program = account(accounts, 6)?;
        expect_signer(cranker)?;
        expect_writable(market_ai)?;
        expect_writable(stake_vault_ai)?;
        expect_writable(vault_token)?;
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;

        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;

        let (transfer_amount_u64, cfg_after) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            // MODE GATE — see the doc comment. Live-only, plus matured-Live.
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;

            // Destination: derived, never caller-chosen. The trust root is the
            // PINNED `constants::STAKE_PROGRAM_ID`, asserted against
            // `stake_pool_ai.owner` before any byte of that account is read.
            // Asset 0's bound `insurance_authority` — the stake pool's
            // `vault_auth` PDA, as recorded by `BindInsuranceAuthority` — then
            // only has to MATCH the PDA re-derived under that pinned program,
            // so it is a pointer we verify rather than a value we trust. A
            // creator can still rotate it (self-rotation is always available;
            // burning `asset_admin` never prevented that), but rotating it can
            // only make this fail, never redirect it. `pool_vault` then comes
            // out of the validated pool's own bytes, so the account the caller
            // passed at index 3 must BE that account or we stop here.
            let asset0_profile = read_oracle_profile_from_view(&group, &cfg, 0)?;
            let (pool_vault, stake_vault_authority) = load_bound_stake_pool(
                program_id,
                market_ai,
                stake_pool_ai,
                &asset0_profile.insurance_authority,
            )?;
            expect_key(stake_vault_ai, &pool_vault)?;
            // Mint/owner/state/canonical-ATA checks on both sides. The dest
            // owner is asserted to be the stake pool's `vault_auth` PDA, so a
            // token account that merely happens to sit at `pool.vault` while
            // being owned by someone else is rejected too.
            verify_withdrawable_token_accounts(
                stake_vault_ai,
                &stake_vault_authority,
                vault_token,
                &vault_authority,
                &cfg,
            )?;
            // W5: this payout is permissionless, so a poisoned destination
            // (delegate / close_authority) must not be usable as a sweep hook.
            verify_permissionless_payout_dest_token_account(stake_vault_ai)?;

            // Claim capacity. Monotonic invariant
            // `insurance_reserve_withdrawn_atoms <= insurance_reserve_accrued_atoms`
            // holds always, so this can only underflow on a corrupt config,
            // which fails closed.
            let claim_capacity = cfg
                .insurance_reserve_accrued_atoms
                .checked_sub(cfg.insurance_reserve_withdrawn_atoms)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            // MANDATORY CLAMP — mirrors `handle_withdraw_protocol_fee`'s
            // `§1.3/N2 clamp` verbatim. `.min(vault)` mirrors
            // `protocol_fee_withdraw_amount`'s
            // second bound: `withdraw_insurance_surplus_delta` rejects
            // `amount > vault` too.
            let engine_available = group
                .header
                .insurance
                .get()
                .saturating_sub(group.header.source_insurance_credit_reserved_total_atoms.get())
                .saturating_sub(group.header.insurance_domain_budget_remaining_total.get());
            let transfer_amount = claim_capacity
                .min(engine_available)
                .min(group.header.vault.get());
            // Zero case: nothing accrued, or the shared surplus pool is dry
            // because another leg got there first. Same error either way — the
            // claim is NOT marked withdrawn, so it stays fully claimable.
            if transfer_amount == 0 {
                return Err(PercolatorError::NoInsuranceReserveToClaim.into());
            }
            let transfer_amount_u64 = amount_to_u64(transfer_amount)?;
            require_token_balance(vault_token, transfer_amount_u64)?;
            // I−a, V−a: the atoms leave both the insurance fund and the vault,
            // because unlike tag 78 they really do leave the program.
            group
                .withdraw_insurance_surplus_not_atomic(transfer_amount)
                .map_err(map_v16_error)?;
            // Advance by the TRANSFERRED amount, never `claim_capacity`.
            cfg.insurance_reserve_withdrawn_atoms = cfg
                .insurance_reserve_withdrawn_atoms
                .checked_add(transfer_amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            group.validate_shape().map_err(map_v16_error)?;
            (transfer_amount_u64, cfg)
        };
        // Unconditional write-back, as in `handle_withdraw_protocol_fee`: every
        // successful call here mutates `insurance_reserve_withdrawn_atoms` (a
        // zero-transfer call returned Err above). Without it the counter resets
        // and the SAME atoms are transferred again on the next call.
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            stake_vault_ai,
            vault_authority_ai,
            transfer_amount_u64,
            signer_seeds,
        )
    }

    #[inline(never)]
    fn handle_close_slab<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let admin_dest = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let vault_token = account(accounts, 2)?;
        let vault_authority_ai = account(accounts, 3)?;
        let dest_token = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;
        expect_signer(admin_dest)?;
        expect_writable(admin_dest)?;
        expect_writable(market_ai)?;
        expect_writable(vault_token)?;
        if admin_dest.key == market_ai.key {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;

        let cfg_pre = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, group) = state::market_view_mut(&mut market_data)?;
            expect_live_authority(&cfg.marketauth, admin_dest.key)?;
            if group.header.mode != 1 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            if group.header.vault.get() != 0
                || group.header.insurance.get() != 0
                || group.header.c_tot.get() != 0
                || group.header.materialized_portfolio_count.get() != 0
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            cfg
        };

        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        let primary_mint = primary_collateral_mint(&cfg_pre);
        verify_vault_token_account(vault_token, &vault_authority, &primary_mint)?;
        let vault_account = unpack_token_account(vault_token)?;
        verify_user_token_account(dest_token, admin_dest.key, &primary_mint)?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        let secondary_close = if cfg_pre.secondary_collateral_mint != [0u8; 32] {
            let secondary_vault_token = account(accounts, 6)?;
            let secondary_dest_token = account(accounts, 7)?;
            expect_writable(secondary_vault_token)?;
            expect_writable(secondary_dest_token)?;
            if secondary_vault_token.key == vault_token.key
                || secondary_dest_token.key == dest_token.key
            {
                return Err(PercolatorError::InvalidVaultAccount.into());
            }
            let secondary_mint = secondary_collateral_mint(&cfg_pre)?;
            verify_vault_token_account(secondary_vault_token, &vault_authority, &secondary_mint)?;
            let secondary_vault_account = unpack_token_account(secondary_vault_token)?;
            verify_user_token_account(secondary_dest_token, admin_dest.key, &secondary_mint)?;
            Some((
                secondary_vault_token,
                secondary_dest_token,
                secondary_vault_account.amount,
            ))
        } else {
            None
        };

        if vault_account.amount > 0 {
            transfer_tokens_signed(
                token_program,
                vault_token,
                dest_token,
                vault_authority_ai,
                vault_account.amount,
                signer_seeds,
            )?;
        }
        let close_ix = spl_token::instruction::close_account(
            token_program.key,
            vault_token.key,
            admin_dest.key,
            vault_authority_ai.key,
            &[],
        )?;
        invoke_signed(
            &close_ix,
            &[
                vault_token.clone(),
                admin_dest.clone(),
                vault_authority_ai.clone(),
                token_program.clone(),
            ],
            signer_seeds,
        )?;

        if let Some((secondary_vault_token, secondary_dest_token, secondary_amount)) =
            secondary_close
        {
            if secondary_amount > 0 {
                transfer_tokens_signed(
                    token_program,
                    secondary_vault_token,
                    secondary_dest_token,
                    vault_authority_ai,
                    secondary_amount,
                    signer_seeds,
                )?;
            }
            let close_secondary_ix = spl_token::instruction::close_account(
                token_program.key,
                secondary_vault_token.key,
                admin_dest.key,
                vault_authority_ai.key,
                &[],
            )?;
            invoke_signed(
                &close_secondary_ix,
                &[
                    secondary_vault_token.clone(),
                    admin_dest.clone(),
                    vault_authority_ai.clone(),
                    token_program.clone(),
                ],
                signer_seeds,
            )?;
        }

        for b in market_ai.try_borrow_mut_data()?.iter_mut() {
            *b = 0;
        }
        let market_lamports = market_ai.lamports();
        **market_ai.lamports.borrow_mut() = 0;
        **admin_dest.lamports.borrow_mut() = admin_dest
            .lamports()
            .checked_add(market_lamports)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_convert_released_pnl<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        with_one_portfolio_view(program_id, accounts, true, |group, portfolio, cfg| {
            if group.header.mode != 0 {
                return Err(V16Error::LockActive);
            }
            if permissionless_resolve_matured_now_view(cfg, group) {
                return Err(V16Error::LockActive);
            }
            // The v16 engine converts the currently released residual-bounded
            // amount atomically. Preserve the wrapper caller cap by staging the
            // conversion and only committing it when the converted amount fits.
            let converted = group.convert_released_pnl_to_capital_not_atomic(portfolio)?;
            if converted == 0 || converted > amount {
                return Err(V16Error::LockActive);
            }
            Ok(())
        })
    }

    #[inline(never)]
    fn handle_cure_and_cancel_close<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        optional_deposit: u128,
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_signer(owner)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;

        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;

        let amount_u64 = if optional_deposit != 0 {
            let source_token = account(accounts, 3)?;
            let vault_token = account(accounts, 4)?;
            let token_program = account(accounts, 5)?;
            expect_writable(source_token)?;
            expect_writable(vault_token)?;
            verify_token_program(token_program)?;
            let cfg_pre =
                state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?.0;
            let mint = primary_collateral_mint(&cfg_pre);
            let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
            verify_user_token_account(source_token, owner.key, &mint)?;
            verify_vault_token_account(vault_token, &vault_authority, &mint)?;
            let amount_u64 = amount_to_u64(optional_deposit)?;
            require_token_balance(source_token, amount_u64)?;
            Some((amount_u64, source_token, vault_token, token_program))
        } else {
            None
        };

        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            // E2: owner==signer OR signer holds the bound NFT (escrowed). NFT trio at base 6.
            let nft = optional_nft_holder_accounts(accounts, 6);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
            group
                .cure_and_cancel_close_not_atomic(&mut portfolio, optional_deposit)
                .map_err(map_v16_error)?;
        }

        if let Some((amount_u64, source_token, vault_token, token_program)) = amount_u64 {
            transfer_tokens(token_program, source_token, vault_token, owner, amount_u64)?;
        }
        Ok(())
    }

    #[inline(never)]
    fn handle_forfeit_recovery_leg<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        b_delta_budget: u128,
    ) -> ProgramResult {
        if b_delta_budget == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        with_one_portfolio_view(program_id, accounts, true, |group, portfolio, _cfg| {
            group
                .forfeit_recovery_leg_not_atomic(portfolio, asset_index as usize, b_delta_budget)
                .map(|_| ())
        })
    }

    #[inline(never)]
    fn handle_rebalance_reduce<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        reduce_q: u128,
    ) -> ProgramResult {
        if reduce_q == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        with_one_portfolio_view(program_id, accounts, true, |group, portfolio, cfg| {
            // #446: restore the upstream maturity gate dropped in our port. Once a
            // market has matured into a permissionless resolve, an owner-signed
            // rebalance-reduce must not still mutate positions — the same gate guards
            // the sibling path at :6661.
            if group.header.mode == 0 && permissionless_resolve_matured_now_view(cfg, group) {
                return Err(V16Error::LockActive);
            }
            group
                .rebalance_reduce_position_not_atomic(
                    portfolio,
                    RebalanceRequestV16 {
                        asset_index: asset_index as usize,
                        reduce_q,
                    },
                )
                .map(|_| ())
        })
    }

    #[inline(never)]
    fn handle_sync_maintenance_fee<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        now_slot: u64,
    ) -> ProgramResult {
        let market_ai = account(accounts, 0)?;
        let portfolio_ai = account(accounts, 1)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;

        let (cfg_pre, _mode, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        if let Some(cranker_portfolio_ai) = accounts.get(2) {
            expect_writable(cranker_portfolio_ai)?;
            expect_owner(cranker_portfolio_ai, program_id)?;
            if cranker_portfolio_ai.key != portfolio_ai.key {
                ensure_portfolio_storage_for_market_slots(cranker_portfolio_ai, max_market_slots)?;
            }
        }
        let authenticated_now_slot = authenticated_slot_or_fallback(now_slot);

        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode == 0 {
                reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            }
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;

            // Protocol-fee RESERVE amendment (~/v17/DECISIONS-LEDGER.md): the
            // cranker reward below is paid from the same unbudgeted insurance
            // surplus the protocol's accrued-but-unwithdrawn claim lives in.
            // `protocol_owed` is threaded through as `additional_reserved` so
            // the engine primitive itself refuses to let this reward dip
            // insurance below the protocol's claim.
            //
            // The LP leg (`lp_fee_accrued - lp_fee_withdrawn`, drained by tag 78)
            // is deliberately NOT reserved here. A maintenance crank is
            // `engine_available`-neutral: `charge_account_fee_current_not_atomic`
            // does `c_tot -= charged; insurance += charged` (engine
            // `v16.rs:13781-13800`), `maintenance_cranker_reward` is bounded by
            // `bps <= 10_000` (validated in `validate_wrapper_config`, via the
            // `config.maintenance_cranker_fee_share_bps > 10_000` reject) so
            // `reward <= charged`, and
            // the retained remainder is credited to the domain budgets 1:1 --
            // hence `d(engine_available) = (c-r) - (c-r) = 0` and this path
            // cannot reduce the surplus the LP claim sits in. Reserving the LP
            // leg here would also make LP fees SENIOR to bad-debt/socialized-loss
            // coverage (this reservation binds only via
            // `credit_account_from_insurance_not_atomic`), contradicting the
            // decision that LP yield is at-risk JUNIOR backing capital, and it
            // would revert the entire `SyncMaintenanceFee` on exactly the
            // distressed markets that most need cranking.
            let protocol_owed = cfg_pre
                .protocol_fee_accrued_atoms
                .saturating_sub(cfg_pre.protocol_fee_withdrawn_atoms);
            if let Some(cranker_portfolio_ai) = accounts.get(2) {
                if cranker_portfolio_ai.key == portfolio_ai.key {
                    let charged = group
                        .sync_account_fee_to_slot_not_atomic(
                            &mut portfolio,
                            authenticated_now_slot,
                            cfg_pre.maintenance_fee_per_slot,
                        )
                        .map_err(map_v16_error)?;
                    let reward =
                        maintenance_cranker_reward(charged, cfg_pre.maintenance_cranker_fee_share_bps)?;
                    if reward != 0 {
                        group
                            .credit_account_from_insurance_not_atomic(
                                &mut portfolio,
                                reward,
                                protocol_owed,
                            )
                            .map_err(map_v16_error)?;
                        group.validate_shape().map_err(map_v16_error)?;
                        portfolio
                            .validate_with_market(&group.as_view())
                            .map_err(map_v16_error)?;
                    }
                    let retained = charged
                        .checked_sub(reward)
                        .ok_or(PercolatorError::EngineCounterUnderflow)?;
                    credit_maintenance_fee_to_active_market_budgets_view(
                        &cfg, &mut group, retained,
                    )?;
                    group.validate_shape().map_err(map_v16_error)?;
                    portfolio
                        .validate_with_market(&group.as_view())
                        .map_err(map_v16_error)?;
                } else {
                    // Finding 15: the separate-cranker path credits maintenance-fee rewards to a
                    // portfolio the caller does not necessarily own. Without an ownership check, any
                    // party can call SyncMaintenanceFee on every user's portfolio and direct all
                    // rewards to an attacker-controlled account, draining insurance systematically.
                    let cranker_owner_ai = account(accounts, 3)?;
                    expect_signer(cranker_owner_ai)?;
                    let mut cranker_data = cranker_portfolio_ai.try_borrow_mut_data()?;
                    let mut cranker = state::portfolio_view_mut_for_market_slots(
                        &mut cranker_data,
                        max_market_slots,
                    )?;
                    expect_portfolio_view_account_key(&cranker, cranker_portfolio_ai.key)?;
                    if cranker_owner_ai.key.to_bytes() != cranker.header.owner {
                        return Err(PercolatorError::Unauthorized.into());
                    }
                    cranker
                        .validate_with_market(&group.as_view())
                        .map_err(map_v16_error)?;
                    let charged = group
                        .sync_account_fee_to_slot_not_atomic(
                            &mut portfolio,
                            authenticated_now_slot,
                            cfg_pre.maintenance_fee_per_slot,
                        )
                        .map_err(map_v16_error)?;
                    let reward =
                        maintenance_cranker_reward(charged, cfg_pre.maintenance_cranker_fee_share_bps)?;
                    if reward != 0 {
                        group
                            .credit_account_from_insurance_not_atomic(
                                &mut cranker,
                                reward,
                                protocol_owed,
                            )
                            .map_err(map_v16_error)?;
                        group.validate_shape().map_err(map_v16_error)?;
                        portfolio
                            .validate_with_market(&group.as_view())
                            .map_err(map_v16_error)?;
                        cranker
                            .validate_with_market(&group.as_view())
                            .map_err(map_v16_error)?;
                    }
                    let retained = charged
                        .checked_sub(reward)
                        .ok_or(PercolatorError::EngineCounterUnderflow)?;
                    credit_maintenance_fee_to_active_market_budgets_view(
                        &cfg, &mut group, retained,
                    )?;
                    group.validate_shape().map_err(map_v16_error)?;
                    portfolio
                        .validate_with_market(&group.as_view())
                        .map_err(map_v16_error)?;
                    cranker
                        .validate_with_market(&group.as_view())
                        .map_err(map_v16_error)?;
                }
            } else {
                let charged = group
                    .sync_account_fee_to_slot_not_atomic(
                        &mut portfolio,
                        authenticated_now_slot,
                        cfg_pre.maintenance_fee_per_slot,
                    )
                    .map_err(map_v16_error)?;
                credit_maintenance_fee_to_active_market_budgets_view(&cfg, &mut group, charged)?;
                group.validate_shape().map_err(map_v16_error)?;
                portfolio
                    .validate_with_market(&group.as_view())
                    .map_err(map_v16_error)?;
            }

            // VULN-03: do NOT deregister-and-close here.
            //
            // handle_sync_maintenance_fee is fully permissionless (no expect_signer on the
            // portfolio owner). If the crank also called
            //   deregister_materialized_portfolio_if_empty + close_portfolio_account_to_market_slab,
            // any third party could force-close an owner's empty (but previously active) portfolio
            // without consent, and the closer would receive that owner's rent-exempt lamports,
            // forcing the owner to re-pay rent to re-open their account (griefing attack).
            //
            // STALE SENTENCE CORRECTED 2026-08-29: this comment used to say the rent goes to
            // `market_ai`, which was true when it was written and stopped being true at #398
            // ("route portfolio rent to closer, not market slab"). The griefing ARGUMENT is
            // unaffected and still the reason this handler does not close accounts — it is
            // about a PERMISSIONLESS caller taking the rent, and after #398 the permissionless
            // caller would take it directly rather than parking it in the market. The
            // destination being `closer` is deliberate and correct for the two paths that DO
            // close: the owner recovers their own deposit on a voluntary close, and marketauth
            // receives it on terminal cleanup (#398 records both as intended destinations).
            //
            // Additionally, partial deregistration without account-close would strand the portfolio
            // in a "registered-but-deregistered" limbo that blocks the owner's subsequent
            // handle_close_portfolio call (deregister_empty_materialized_portfolio_not_atomic would
            // return LockActive on second attempt, trapping rent permanently).
            //
            // Account closure is gated on owner or marketauth consent in handle_close_portfolio,
            // which already provides the signer-check + deregister + account-close sequence.
        };
        Ok(())
    }

    #[inline(never)]
    fn handle_resolve_market<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
        if group.header.mode != 0 {
            return Err(PercolatorError::EngineLockActive.into());
        }
        expect_live_authority(&cfg.marketauth, admin.key)?;
        let slot = Clock::get()
            .map(|c| c.slot)
            .unwrap_or(group.header.current_slot.get());
        if slot < group.header.current_slot.get() {
            return Err(PercolatorError::EngineStale.into());
        }
        group
            .resolve_market_not_atomic(slot)
            .map_err(map_v16_error)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_update_authority<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        new_pubkey: [u8; 32],
    ) -> ProgramResult {
        let current = account(accounts, 0)?;
        let new_authority = account(accounts, 1)?;
        let market_ai = account(accounts, 2)?;
        expect_signer(current)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;

        if new_pubkey == [0u8; 32] {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // Incoming key must co-sign (proves control).
        expect_signer(new_authority)?;
        if new_authority.key.to_bytes() != new_pubkey {
            return Err(PercolatorError::Unauthorized.into());
        }

        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, current.key)?;
        cfg.marketauth = new_pubkey;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_update_asset_authority<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        kind: u8,
        new_pubkey: [u8; 32],
    ) -> ProgramResult {
        let current = account(accounts, 0)?;
        let new_authority = account(accounts, 1)?;
        let market_ai = account(accounts, 2)?;
        expect_signer(current)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;

        // A non-zero incoming key must co-sign (proves control); burning to 0 needs only the rotator.
        if new_pubkey != [0u8; 32] {
            expect_signer(new_authority)?;
            if new_authority.key.to_bytes() != new_pubkey {
                return Err(PercolatorError::Unauthorized.into());
            }
        }

        let asset_index = asset_index as usize;
        // Asset 0 carries a real stored profile (asset_admin bootstrapped to the market admin) and is
        // rotated/burned here exactly like permissionless assets 1..N.

        let mut data = market_ai.try_borrow_mut_data()?;
        let (cfg, mut group) = state::market_view_mut(&mut data)?;
        if group.header.mode != 0 {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if asset_index >= group.header.config.max_market_slots.get() as usize {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let mut profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;

        // The asset's own cold-storage admin may rotate ANY of its authorities, and only the admin
        // authority itself may be burned to 0; otherwise the current holder of THIS authority
        // self-rotates. Scoped to this asset's profile only — it can never act on another asset.
        let admin_signed =
            profile.asset_admin != [0u8; 32] && profile.asset_admin == current.key.to_bytes();
        let current_value = match kind {
            ASSET_AUTH_ADMIN => profile.asset_admin,
            ASSET_AUTH_INSURANCE => profile.insurance_authority,
            ASSET_AUTH_INSURANCE_OPERATOR => profile.insurance_operator,
            ASSET_AUTH_BACKING_BUCKET => profile.backing_bucket_authority,
            ASSET_AUTH_ORACLE => profile.oracle_authority,
            _ => return Err(PercolatorError::InvalidInstruction.into()),
        };
        // Required domain authorities must stay live after activation. A zero insurance/backing/oracle
        // authority can strand funds or oracle liveness during wind-down; only the cold-storage
        // asset_admin may be intentionally burned.
        if new_pubkey == [0u8; 32] && kind != ASSET_AUTH_ADMIN {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // ── #437/#439: the admin bypass is an allow-list of STATES, not of KINDS. ──
        //
        // History of this guard, one leg at a time: #414 found `asset_admin` could take
        // `insurance_authority`; #416/#417 added `insurance_operator` to the same
        // `matches!`; #424 bolted a separate custody check onto `backing_bucket_authority`.
        // Each fix NAMED the kind it was closing, which left the rule "bypass everything
        // except the names we happened to think of". #437/#439 is the bill for that: the
        // `matches!` listed two of the five kinds, so ORACLE and BACKING_BUCKET skipped
        // `expect_live_authority` entirely and `asset_admin` could rotate them away from a
        // holder that never signed — for ORACLE, straight into ConfigureAuthMark (which
        // itself switches `oracle_mode`, so no prior auth-mark configuration is needed) and
        // PushAuthMark, i.e. the asset's whole price surface.
        //
        // So the rule is INVERTED rather than extended. The bypass is now permitted only
        // for a state in which there IS NO HOLDER TO DEFEND. A sixth authority kind added
        // later is therefore guarded on the day it is added, instead of being silently
        // exempt until someone files the next issue.
        //
        // Two unheld states exist:
        //
        //  1. `current_value == 0` — bootstrapping. Kept from the previous rule. In
        //     practice every activation path already fills all four sub-authorities
        //     (`domain_authority_fields_complete`, :6799; `activate_dynamic_asset_slot`,
        //     :2180) and non-admin kinds cannot be burned back to 0 (the check directly
        //     above), so this is defence in depth rather than a live path.
        //
        //  2. The LP-vault registry PDA holding `backing_bucket_authority` AFTER the vault
        //     has been closed. `handle_create_lp_vault`'s FIND-1 binding parks this
        //     authority on `registry_pda`, an address NOTHING can sign for — no path CPIs
        //     back into this program to sign as it. Under a holder-consent rule that is not
        //     "a holder that must consent", it is a permanent lock, and #424's own comment
        //     records why the lock must not be permanent: CloseLpVault leaves the LP mint
        //     on-chain (so CreateLpVault can never re-run) and leaves the dead-share floor's
        //     backing residue in the bucket, and reclaiming that residue — plus reaching
        //     CloseSlab, which needs `header.vault == 0` — requires re-pointing this
        //     authority at a signable key. Treating an unsignable-PDA holder as unheld is
        //     what keeps wind-down reachable while the inversion closes ORACLE.
        //
        // #424's hard reject is preserved verbatim inside (2) and still fires FIRST: while
        // the registry is live and names THIS asset, the rotation is refused outright, not
        // merely consent-checked. Scoped to the vault's own asset, so an unrelated slot that
        // merely carries this value (a lifecycle activation can plant it verbatim, with no
        // co-signature) is not welded shut. The registry account is consulted only on this
        // branch and its ABSENCE rejects — omitting it cannot skip the guard, and
        // `expect_key` pins the address so no substitute is accepted.
        //
        // The whole block is gated on `admin_signed`, which is behaviour-preserving for
        // every other caller and keeps `derive_lp_vault_registry`'s find_program_address off
        // the hot path: a non-admin signer took `expect_live_authority` before reaching the
        // #424 check under the old ordering too (the registry PDA cannot sign, so that call
        // always returned Unauthorized first), so no error code moves.
        //
        // WHAT THIS COSTS. `asset_admin` can no longer re-point a HELD authority without
        // that holder's signature — including to recover from a holder key that is lost. The
        // insurance legs have already paid that price since #416/#417; this makes it uniform
        // across all five kinds. Two escape hatches remain and are unaffected: for assets
        // 1..N, `marketauth` can RETIRE and re-ACTIVATE the slot, which rewrites all four
        // sub-authorities (:13061-13065); and delegating to a multisig/PDA that CAN sign
        // keeps rotation available by construction. Asset 0 has no such hatch, which is
        // deliberate — the same re-activation branch is barred from asset 0 to protect the
        // creator-fee claim (:13029). An operator who wants revocable delegation should
        // therefore hand out `insurance_operator`-style roles from a signable custodian
        // rather than expect the admin to claw them back.
        let admin_bypass_permitted = admin_signed
            && (current_value == [0u8; 32] || {
                if kind == ASSET_AUTH_BACKING_BUCKET {
                    let (registry_pda, _) =
                        state::derive_lp_vault_registry(program_id, market_ai.key);
                    if current_value == registry_pda.to_bytes() {
                        let registry_ai = account(accounts, 3)?;
                        expect_key(registry_ai, &registry_pda)?;
                        let registry_data = registry_ai.try_borrow_data()?;
                        if state::is_initialized(&registry_data) {
                            let registry = state::read_lp_vault_registry(&registry_data)?;
                            if registry.domain as usize / 2 == asset_index {
                                return Err(PercolatorError::LpVaultAuthorityMismatch.into());
                            }
                        }
                        // Live-but-other-asset, or closed: no signer exists behind this
                        // value, so there is no consent to obtain.
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            });
        if !admin_bypass_permitted {
            expect_live_authority(&current_value, current.key)?;
        }
        match kind {
            ASSET_AUTH_ADMIN => profile.asset_admin = new_pubkey,
            ASSET_AUTH_INSURANCE => profile.insurance_authority = new_pubkey,
            ASSET_AUTH_INSURANCE_OPERATOR => profile.insurance_operator = new_pubkey,
            ASSET_AUTH_BACKING_BUCKET => profile.backing_bucket_authority = new_pubkey,
            ASSET_AUTH_ORACLE => profile.oracle_authority = new_pubkey,
            _ => return Err(PercolatorError::InvalidInstruction.into()),
        }
        write_oracle_profile_to_view(&mut group, asset_index, &profile)?;
        Ok(())
    }

    #[inline(never)]
    fn handle_update_base_unit_mints<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        primary_mint: [u8; 32],
        secondary_mint: [u8; 32],
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let primary_mint_ai = account(accounts, 2)?;
        let secondary_mint_ai = account(accounts, 3)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if primary_mint == [0u8; 32]
            || secondary_mint == [0u8; 32]
            || primary_mint == secondary_mint
        {
            return Err(PercolatorError::InvalidMint.into());
        }
        let primary_key = Pubkey::new_from_array(primary_mint);
        let secondary_key = Pubkey::new_from_array(secondary_mint);
        expect_key(primary_mint_ai, &primary_key)?;
        expect_key(secondary_mint_ai, &secondary_key)?;
        // #447: the primary and secondary collateral mints are both denominated in
        // engine base units. Mismatched decimals silently rescale every deposit and
        // withdrawal through the secondary mint. Upstream rejects it here; our port
        // dropped the check by calling `verify_mint`, which discards the mint it
        // unpacks.
        let primary_mint_state = unpack_mint(primary_mint_ai)?;
        let secondary_mint_state = unpack_mint(secondary_mint_ai)?;
        if primary_mint_state.decimals != secondary_mint_state.decimals {
            return Err(PercolatorError::InvalidMint.into());
        }

        let mut data = market_ai.try_borrow_mut_data()?;
        let mut cfg = {
            let (cfg, group) = state::market_view_mut(&mut data)?;
            expect_live_authority(&cfg.marketauth, authority.key)?;
            if group.header.vault.get() != 0
                || group.header.c_tot.get() != 0
                || group.header.insurance.get() != 0
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            cfg
        };
        cfg.collateral_mint = primary_mint;
        cfg.secondary_collateral_mint = secondary_mint;
        state::write_wrapper_config(&mut data, &cfg)
    }

    #[inline(never)]
    fn handle_swap_secondary_for_primary<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let primary_source_token = account(accounts, 2)?;
        let primary_vault_token = account(accounts, 3)?;
        let secondary_dest_token = account(accounts, 4)?;
        let secondary_vault_token = account(accounts, 5)?;
        let vault_authority_ai = account(accounts, 6)?;
        let token_program = account(accounts, 7)?;
        expect_signer(authority)?;
        expect_writable(primary_source_token)?;
        expect_writable(primary_vault_token)?;
        expect_writable(secondary_dest_token)?;
        expect_writable(secondary_vault_token)?;
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;
        if amount == 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let amount_u64 = amount_to_u64(amount)?;

        // VULN-02 (#355): reject when the market is not Live (resolved/locked), mirroring
        // handle_deposit and every other engine-touching handler. Without this guard the
        // secondary->primary swap stayed callable after ResolveMarket (the handler read the
        // mode but discarded it and never engaged the engine lock).
        let (cfg, mode, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        expect_live_authority(&cfg.marketauth, authority.key)?;
        let primary_mint = primary_collateral_mint(&cfg);
        let secondary_mint = secondary_collateral_mint(&cfg)?;
        let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        verify_user_token_account(primary_source_token, authority.key, &primary_mint)?;
        verify_vault_token_account(primary_vault_token, &vault_authority, &primary_mint)?;
        verify_user_token_account(secondary_dest_token, authority.key, &secondary_mint)?;
        verify_vault_token_account(secondary_vault_token, &vault_authority, &secondary_mint)?;
        require_token_balance(primary_source_token, amount_u64)?;
        require_token_balance(secondary_vault_token, amount_u64)?;

        transfer_tokens(
            token_program,
            primary_source_token,
            primary_vault_token,
            authority,
            amount_u64,
        )?;
        let bump_arr = [bump];
        let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
        transfer_tokens_signed(
            token_program,
            secondary_vault_token,
            secondary_dest_token,
            vault_authority_ai,
            amount_u64,
            signer_seeds,
        )
    }

    fn canonicalize_retired_asset_slot_view(
        group: &mut state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> ProgramResult {
        let slot = group
            .markets
            .get_mut(asset_index)
            .ok_or(PercolatorError::InvalidInstruction)?;
        let asset = slot.engine.asset.try_to_runtime().map_err(map_v16_error)?;
        if asset.lifecycle != percolator::AssetLifecycleV16::Retired
            || asset.market_id == 0
            || asset.retired_slot == 0
            || slot.engine.insurance_domain_budget_long.get() != 0
            || slot.engine.insurance_domain_budget_short.get() != 0
            || slot.engine.insurance_domain_spent_long.get() != 0
            || slot.engine.insurance_domain_spent_short.get() != 0
            || slot.engine.pending_domain_loss_barrier_long.get() != 0
            || slot.engine.pending_domain_loss_barrier_short.get() != 0
        {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let backing_long = slot
            .engine
            .backing_long
            .try_to_runtime()
            .map_err(map_v16_error)?;
        let backing_short = slot
            .engine
            .backing_short
            .try_to_runtime()
            .map_err(map_v16_error)?;
        if backing_long.utilization_fee_earnings != 0 || backing_short.utilization_fee_earnings != 0
        {
            return Err(PercolatorError::EngineLockActive.into());
        }

        let mut canonical_asset = percolator::AssetStateV16::default();
        canonical_asset.market_id = asset.market_id;
        canonical_asset.retired_slot = asset.retired_slot;
        canonical_asset.lifecycle = percolator::AssetLifecycleV16::Retired;
        canonical_asset.raw_oracle_target_price = asset.raw_oracle_target_price;
        canonical_asset.effective_price = asset.effective_price;
        canonical_asset.fund_px_last = asset.fund_px_last;
        canonical_asset.slot_last = asset.slot_last;

        let mut canonical_slot =
            percolator::EngineAssetSlotV16Account::empty_for_market(asset.market_id);
        canonical_slot.asset = percolator::AssetStateV16Account::from_runtime(&canonical_asset);
        slot.engine = canonical_slot;
        Ok(())
    }

    #[inline(never)]
    fn handle_restart_asset_oracle<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if now_slot == 0 || initial_price == 0 || initial_price > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let asset_index = asset_index as usize;
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            if asset_index >= configured_slots || asset_index >= group.markets.len() {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            if authenticated_slot < group.header.current_slot.get() {
                return Err(PercolatorError::EngineStale.into());
            }
            if group.markets[asset_index].engine.asset.lifecycle != ASSET_LIFECYCLE_RECOVERY {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let existing_profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;
            expect_live_authority(&existing_profile.asset_admin, authority.key)?;
            group
                .restart_empty_asset_preserving_insurance_budget_not_atomic(
                    asset_index,
                    initial_price,
                    authenticated_slot,
                )
                .map_err(map_v16_error)?;

            let mut profile = preserve_backing_fee_policy(
                state::manual_asset_oracle_profile(initial_price, authenticated_slot),
                &existing_profile,
            );
            profile.asset_admin = existing_profile.asset_admin;
            profile.insurance_authority = existing_profile.insurance_authority;
            profile.insurance_operator = existing_profile.insurance_operator;
            profile.backing_bucket_authority = existing_profile.backing_bucket_authority;
            profile.oracle_authority = existing_profile.oracle_authority;
            if asset_index == 0 {
                mirror_manual_profile_to_base_config(&mut cfg, &profile, true);
            }
            write_oracle_profile_to_view(&mut group, asset_index, &profile)?;
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_update_asset_lifecycle<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        action: u8,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
        insurance_authority: [u8; 32],
        insurance_operator: [u8; 32],
        backing_bucket_authority: [u8; 32],
        oracle_authority: [u8; 32],
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;

        let asset_index = asset_index as usize;
        let (cfg_pre, mode_pre, configured_slots_pre, capacity_pre) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode_pre != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        // Same funding warning as InitMarket: activating an asset is creating a
        // market, and an asset priced below the funding threshold has the
        // identical silent-dead-funding failure. `max_abs_funding_e9_per_slot`
        // and `max_accrual_dt_slots` are market-wide; only `initial_price` varies
        // per asset, so a market can be perfectly fundable at asset 0's price and
        // dead-funded at asset 5's.
        if action == ASSET_ACTION_ACTIVATE {
            let (max_abs_funding_e9_per_slot, max_accrual_dt_slots) =
                state::read_engine_funding_bounds(&market_ai.try_borrow_data()?)?;
            warn_if_funding_cannot_accrue(
                max_abs_funding_e9_per_slot,
                max_accrual_dt_slots,
                initial_price,
            );
        }
        let is_asset_authority =
            cfg_pre.marketauth != [0u8; 32] && cfg_pre.marketauth == authority.key.to_bytes();
        let permissionless_reuse_target = action == ASSET_ACTION_ACTIVATE
            && !is_asset_authority
            && asset_index < configured_slots_pre
            && cfg_pre.free_market_slot_count != 0;
        if action == ASSET_ACTION_ACTIVATE
            && (asset_index == configured_slots_pre || permissionless_reuse_target)
        {
            let authenticated_slot = authenticated_slot_or_fallback(now_slot);
            let append_activation = asset_index == configured_slots_pre;
            if append_activation && cfg_pre.free_market_slot_count != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let init_fee = if is_asset_authority {
                0
            } else {
                let fee = permissionless_market_init_fee_for_asset(
                    cfg_pre.permissionless_market_init_fee,
                    asset_index,
                )?;
                if fee == 0 {
                    return Err(PercolatorError::Unauthorized.into());
                }
                fee
            };
            let transfer_accounts = if init_fee == 0 {
                None
            } else {
                let source_token = account(accounts, 2)?;
                let vault_token = account(accounts, 3)?;
                let token_program = account(accounts, 4)?;
                expect_writable(source_token)?;
                expect_writable(vault_token)?;
                verify_token_program(token_program)?;
                let mint = primary_collateral_mint(&cfg_pre);
                let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
                verify_user_token_account(source_token, authority.key, &mint)?;
                verify_vault_token_account(vault_token, &vault_authority, &mint)?;
                let amount_u64 = amount_to_u64(init_fee)?;
                require_token_balance(source_token, amount_u64)?;
                Some((source_token, vault_token, token_program, amount_u64))
            };
            if asset_index >= capacity_pre {
                let new_len = state::market_account_len_for_capacity(asset_index + 1)?;
                market_ai.realloc(new_len, true)?;
            }
            // CEI fix: transfer the init fee BEFORE mutating engine state.
            // A Token-2022 transfer hook fires during the CPI and could re-enter this program
            // while seeing already-committed engine effects (active slot, decremented
            // free_market_slot_count). Performing the transfer first means the hook fires against
            // the pre-activation state, eliminating the re-entrancy window.
            if let Some((source_token, vault_token, token_program, amount_u64)) = transfer_accounts {
                transfer_tokens(
                    token_program,
                    source_token,
                    vault_token,
                    authority,
                    amount_u64,
                )?;
            }
            {
                let mut data = market_ai.try_borrow_mut_data()?;
                let mut reuse_cfg_after = None;
                let mut reuse_activated = false;
                {
                    let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
                    let still_asset_authority =
                        cfg.marketauth != [0u8; 32] && cfg.marketauth == authority.key.to_bytes();
                    if !still_asset_authority {
                        let expected_fee = permissionless_market_init_fee_for_asset(
                            cfg.permissionless_market_init_fee,
                            asset_index,
                        )?;
                        if expected_fee == 0 || expected_fee != init_fee {
                            return Err(PercolatorError::Unauthorized.into());
                        }
                    }
                    if group.header.mode != 0 {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                    let configured_slots = group.header.config.max_market_slots.get() as usize;
                    if asset_index == configured_slots {
                        if cfg.free_market_slot_count != 0 {
                            return Err(PercolatorError::EngineLockActive.into());
                        }
                    } else if !still_asset_authority
                        && asset_index < configured_slots
                        && cfg.free_market_slot_count != 0
                    {
                        if group.markets[asset_index].engine.asset.lifecycle
                            != ASSET_LIFECYCLE_RETIRED
                        {
                            // Slot is below max_market_slots and NOT retired. If it is
                            // one of the three IN-SERVICE lifecycles, say so precisely;
                            // anything else keeps the prior generic code so no other
                            // rejection is silently reclassified.
                            return Err(match group.markets[asset_index].engine.asset.lifecycle {
                                ASSET_LIFECYCLE_ACTIVE
                                | ASSET_LIFECYCLE_DRAIN_ONLY
                                | ASSET_LIFECYCLE_RECOVERY => {
                                    PercolatorError::AssetSlotAlreadyConfigured.into()
                                }
                                _ => PercolatorError::EngineLockActive.into(),
                            });
                        }
                        // Reject zero domain authorities, mirroring the append path
                        // (activate_dynamic_asset_slot, ~line 1475). A zero
                        // insurance_authority makes that domain's insurance budget
                        // withdrawable by nobody (terminal_insurance_remaining rejects a
                        // zero authority), permanently bricking CloseSlab (Finding F).
                        if !domain_authority_fields_complete(
                            insurance_authority,
                            insurance_operator,
                            backing_bucket_authority,
                            oracle_authority,
                        ) {
                            return Err(PercolatorError::InvalidInstruction.into());
                        }
                        group
                            .header
                            .activate_empty_market_slot_not_atomic(
                                asset_index as u32,
                                &mut group.markets[asset_index],
                                initial_price,
                                authenticated_slot,
                            )
                            .map_err(map_v16_error)?;
                        cfg.free_market_slot_count = cfg
                            .free_market_slot_count
                            .checked_sub(1)
                            .ok_or(PercolatorError::EngineCounterUnderflow)?;
                        let mut profile =
                            state::manual_asset_oracle_profile(initial_price, authenticated_slot);
                        profile.insurance_authority = insurance_authority;
                        profile.insurance_operator = insurance_operator;
                        profile.backing_bucket_authority = backing_bucket_authority;
                        profile.oracle_authority = oracle_authority;
                        // Per-asset cold-storage admin: bootstrap to the activator; it can later be
                        // rotated to a cold key or burned via UpdateAssetAuthority.
                        profile.asset_admin = authority.key.to_bytes();
                        write_oracle_profile_to_view_if_separate(
                            &mut group,
                            asset_index,
                            &profile,
                        )?;
                        group.validate_shape().map_err(map_v16_error)?;
                        reuse_cfg_after = Some(cfg);
                        reuse_activated = true;
                    } else {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                }
                if let Some(cfg) = reuse_cfg_after {
                    state::write_wrapper_config(&mut data, &cfg)?;
                }
                if reuse_activated && init_fee != 0 {
                    let (_cfg, mut group) = state::market_view_mut(&mut data)?;
                    deposit_market_zero_insurance_view(&mut group, init_fee)?;
                    group.validate_shape().map_err(map_v16_error)?;
                }
                let (_cfg, _mode, configured_slots, _) =
                    state::read_market_config_mode_and_capacity(&data)?;
                if !reuse_activated && asset_index == configured_slots {
                    let mut profile = state::activate_dynamic_asset_slot(
                        &mut data,
                        asset_index,
                        authenticated_slot,
                        initial_price,
                        insurance_authority,
                        insurance_operator,
                        backing_bucket_authority,
                        oracle_authority,
                    )?;
                    // Per-asset cold-storage admin: bootstrap to the activator (the permissionless
                    // creator or the asset_authority); rotatable / burnable via UpdateAssetAuthority.
                    profile.asset_admin = authority.key.to_bytes();
                    state::write_asset_oracle_profile(&mut data, asset_index, &profile)?;
                    if init_fee != 0 {
                        let (_cfg, mut group) = state::market_view_mut(&mut data)?;
                        deposit_market_zero_insurance_view(&mut group, init_fee)?;
                        group.validate_shape().map_err(map_v16_error)?;
                    }
                }
            }
            return Ok(());
        }
        if action == ASSET_ACTION_SHUTDOWN {
            if now_slot == 0 || initial_price != 0 || cfg_pre.force_close_delay_slots == 0 {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let authenticated_slot = authenticated_slot_or_fallback(now_slot);
            let cfg_after = {
                let mut data = market_ai.try_borrow_mut_data()?;
                let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
                if group.header.mode != 0 {
                    return Err(PercolatorError::EngineLockActive.into());
                }
                let configured_slots = group.header.config.max_market_slots.get() as usize;
                if asset_index >= configured_slots || asset_index >= group.markets.len() {
                    return Err(PercolatorError::InvalidInstruction.into());
                }
                let mut profile = read_oracle_profile_from_view(&group, &cfg, asset_index)?;
                let marketauth_authorized = live_authority_matches(&cfg.marketauth, authority.key);
                let asset_admin_authorized =
                    live_authority_matches(&profile.asset_admin, authority.key);
                if !marketauth_authorized && !asset_admin_authorized {
                    return Err(PercolatorError::Unauthorized.into());
                }
                if authenticated_slot < group.header.current_slot.get() {
                    return Err(PercolatorError::EngineStale.into());
                }
                match group.markets[asset_index].engine.asset.lifecycle {
                    ASSET_LIFECYCLE_ACTIVE | ASSET_LIFECYCLE_DRAIN_ONLY => {
                        let frozen_mark = group.markets[asset_index]
                            .engine
                            .asset
                            .effective_price
                            .get();
                        if frozen_mark == 0 || frozen_mark > percolator::MAX_ORACLE_PRICE {
                            return Err(PercolatorError::OracleInvalid.into());
                        }
                        group
                            .force_asset_recovery_not_atomic(asset_index, authenticated_slot)
                            .map_err(map_v16_error)?;
                        profile.mark_ewma_e6 = frozen_mark;
                        profile.mark_ewma_last_slot = authenticated_slot;
                        profile.oracle_target_price_e6 = frozen_mark;
                        profile.oracle_target_publish_time = 0;
                        profile.last_good_oracle_slot = authenticated_slot;
                        if asset_index == 0 {
                            mirror_manual_profile_to_base_config(&mut cfg, &profile, true);
                            write_oracle_profile_to_view(&mut group, asset_index, &profile)?;
                        } else {
                            write_oracle_profile_to_view_if_separate(
                                &mut group,
                                asset_index,
                                &profile,
                            )?;
                        }
                    }
                    ASSET_LIFECYCLE_RECOVERY => {}
                    _ => return Err(PercolatorError::EngineLockActive.into()),
                }
                group.validate_shape().map_err(map_v16_error)?;
                cfg
            };
            return state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after);
        }
        // Activate (privileged, fee-free) / retire are gated solely on `marketauth`.
        if !live_authority_matches(&cfg_pre.marketauth, authority.key) {
            return Err(PercolatorError::Unauthorized.into());
        }
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        if oracle_v16::permissionless_stale_matured(&cfg_pre, authenticated_slot) {
            return Err(PercolatorError::OracleStale.into());
        }

        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let existing_profile = state::read_asset_oracle_profile(&data, asset_index)?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if !live_authority_matches(&cfg.marketauth, authority.key) {
                return Err(PercolatorError::Unauthorized.into());
            }
            // Pre-collapse this was true only when the *admin* key (distinct from the *asset_authority*
            // key) retired an asset; the market authority itself was always "asset-authorized" so this
            // branch never fired for the init signer. With admin and asset_authority collapsed into the
            // single `marketauth`, the holder is always asset-authorized, so this stays false — an exact
            // 1:1 preservation of the prior single-init-key behavior (no widening, no narrowing).
            let admin_retire = false;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let configured_slots = group.header.config.max_market_slots.get() as usize;
            if asset_index >= configured_slots {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let mut reset_profile = None;
            match action {
                ASSET_ACTION_ACTIVATE => {
                    if !domain_authority_fields_complete(
                        insurance_authority,
                        insurance_operator,
                        backing_bucket_authority,
                        oracle_authority,
                    ) {
                        return Err(PercolatorError::InvalidInstruction.into());
                    }
                    // Reaching here means asset_index < max_market_slots (the
                    // append path returned earlier). Only a RETIRED slot may be
                    // re-activated; a slot that is already Active/DrainOnly/
                    // Recovery is in service and the engine's
                    // `activate_empty_market_slot_not_atomic` would reject it
                    // with the generic LockActive. `InitMarket` pre-configures
                    // slots 0..max_portfolio_assets as Active, so on a market
                    // with max_portfolio_assets > 1 every one of those indices
                    // lands here. Answer accurately instead.
                    //
                    // Scoped to the three IN-SERVICE lifecycles only: a Disabled
                    // slot is still a legal activation target for the engine, so
                    // it must keep falling through untouched.
                    if matches!(
                        group.markets[asset_index].engine.asset.lifecycle,
                        ASSET_LIFECYCLE_ACTIVE | ASSET_LIFECYCLE_DRAIN_ONLY | ASSET_LIFECYCLE_RECOVERY
                    ) {
                        return Err(PercolatorError::AssetSlotAlreadyConfigured.into());
                    }
                    // CREATOR-FEE-CLAIM INVARIANT (2026-07-24, defense in depth).
                    // Asset 0's `asset_admin` is the ONLY key that can claim accrued creator
                    // fees (tag 90 `WithdrawCreatorFee` reads asset index 0). This re-activation
                    // branch is the one path that rewrites the per-asset authorities on an
                    // ALREADY-EXISTING slot -- including `profile.asset_admin = authority.key`
                    // below -- so it must never reach asset 0. Otherwise `marketauth`, which on
                    // a STAKED market is the stake-pool PDA, could rewrite asset-0's asset_admin
                    // and steal the creator's claim (exactly the theft tag 90 declines to enable
                    // by refusing `marketauth` as a gate). Note this branch is why `asset_admin`
                    // could NOT be rewritten out from under the creator by the stake flow.
                    //
                    // This is ALREADY unreachable today, but only EMERGENTLY: the in-service
                    // check directly above rejects ACTIVE/DRAIN_ONLY/RECOVERY, and
                    // ASSET_ACTION_RETIRE rejects `asset_index == 0`, so asset 0 can never be
                    // RETIRED and therefore never re-activated. That safety spans two distant
                    // checks and is asserted nowhere. Pin it here so a future lifecycle change
                    // (e.g. adding a Disabled state, or relaxing the RETIRE guard) cannot
                    // silently re-open the theft path.
                    if asset_index == 0 {
                        return Err(PercolatorError::AssetSlotAlreadyConfigured.into());
                    }
                    let was_retired = group.markets[asset_index].engine.asset.lifecycle
                        == ASSET_LIFECYCLE_RETIRED;
                    let preserved_policy_count =
                        backing_fee_policy_count_from_profile(&existing_profile);
                    group
                        .header
                        .activate_empty_market_slot_not_atomic(
                            asset_index as u32,
                            &mut group.markets[asset_index],
                            initial_price,
                            authenticated_slot,
                        )
                        .map_err(map_v16_error)?;
                    if was_retired && cfg.free_market_slot_count != 0 {
                        cfg.free_market_slot_count -= 1;
                    }
                    if was_retired {
                        add_backing_fee_policy_count(&mut cfg, preserved_policy_count)?;
                    }
                    let mut profile = preserve_backing_fee_policy(
                        state::manual_asset_oracle_profile(initial_price, authenticated_slot),
                        &existing_profile,
                    );
                    profile.insurance_authority = insurance_authority;
                    profile.insurance_operator = insurance_operator;
                    profile.backing_bucket_authority = backing_bucket_authority;
                    profile.oracle_authority = oracle_authority;
                    profile.asset_admin = authority.key.to_bytes();
                    if asset_index == 0 {
                        mirror_manual_profile_to_base_config(&mut cfg, &profile, true);
                    }
                    reset_profile = Some(profile);
                }
                ASSET_ACTION_DRAIN_ONLY => {
                    if now_slot != 0 || initial_price != 0 {
                        return Err(PercolatorError::InvalidInstruction.into());
                    }
                    group
                        .mark_asset_drain_only_not_atomic(asset_index)
                        .map_err(map_v16_error)?;
                }
                ASSET_ACTION_RETIRE => {
                    if asset_index == 0 || now_slot == 0 || initial_price != 0 {
                        return Err(PercolatorError::InvalidInstruction.into());
                    }
                    if admin_retire {
                        shutdown_asset_empty_and_matured_at_slot_view(
                            &cfg,
                            &group,
                            asset_index,
                            authenticated_slot,
                        )?;
                    }
                    if authenticated_slot < group.header.current_slot.get() {
                        return Err(PercolatorError::EngineStale.into());
                    }
                    let lifecycle = group.markets[asset_index].engine.asset.lifecycle;
                    let retired_policy_count =
                        backing_fee_policy_count_from_profile(&existing_profile);
                    match lifecycle {
                        ASSET_LIFECYCLE_ACTIVE
                        | ASSET_LIFECYCLE_DRAIN_ONLY
                        | ASSET_LIFECYCLE_RECOVERY => {
                            group
                                .retire_empty_asset_not_atomic(asset_index, authenticated_slot)
                                .map_err(map_v16_error)?;
                            canonicalize_retired_asset_slot_view(&mut group, asset_index)?;
                            cfg.free_market_slot_count = cfg
                                .free_market_slot_count
                                .checked_add(1)
                                .ok_or(PercolatorError::EngineCounterOverflow)?;
                            subtract_backing_fee_policy_count(&mut cfg, retired_policy_count)?;
                        }
                        ASSET_LIFECYCLE_RETIRED => {
                            group
                                .retire_empty_asset_not_atomic(asset_index, authenticated_slot)
                                .map_err(map_v16_error)?;
                            canonicalize_retired_asset_slot_view(&mut group, asset_index)?;
                        }
                        _ => return Err(PercolatorError::EngineLockActive.into()),
                    }
                    let price = group.markets[asset_index]
                        .engine
                        .asset
                        .effective_price
                        .get();
                    let profile = preserve_backing_fee_policy(
                        state::manual_asset_oracle_profile(price, authenticated_slot),
                        &existing_profile,
                    );
                    if asset_index == 0 {
                        mirror_manual_profile_to_base_config(&mut cfg, &profile, false);
                    }
                    reset_profile = Some(profile);
                }
                _ => return Err(PercolatorError::InvalidInstruction.into()),
            }
            if let Some(profile) = reset_profile {
                write_oracle_profile_to_view(&mut group, asset_index, &profile)?;
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_finalize_reset_side<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        side: u8,
    ) -> ProgramResult {
        let market_ai = account(accounts, 0)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let side = decode_side(side)?;
        let mut data = market_ai.try_borrow_mut_data()?;
        let (_cfg, mut group) = state::market_view_mut(&mut data)?;
        group
            .finalize_side_reset_not_atomic(asset_index as usize, side)
            .map_err(map_v16_error)
    }

    #[inline(never)]
    fn handle_refine_resolved_unreceipted_bound<'a>(
        _program_id: &Pubkey,
        _accounts: &'a [AccountInfo<'a>],
        _decrease_num: u128,
    ) -> ProgramResult {
        // SECURITY (#313): the externally-callable refine is DISABLED. The arbitrary
        // admin `decrease_num` was guarded only by the monotone-rate check, which
        // PASSES in the haircut regime (draining the unreceipted reserve shrinks the
        // rate denominator while the numerator stays clamped at residual*SCALE, so the
        // rate only rises) — letting `marketauth` over-drain `terminal_claim_bound_unreceipted_num`
        // below outstanding winner claims and permanently strand them (close_resolved →
        // RecoveryRequired). No correct static floor exists: source-backed realization
        // already reduces the reserve with no tracked quantity to distinguish a malicious
        // further decrease. The ONLY accounting-faithful refinement is the INTERNAL one in
        // `realize_source_backed_claims_for_resolved_close_not_atomic` (engine
        // `refine_resolved_unreceipted_bound_not_atomic`, clamped to realized face as
        // receipts realize), which is a direct engine call and is unaffected. Reject the
        // external entry point. Do NOT re-enable without a per-claim outstanding-obligation floor.
        Err(PercolatorError::InvalidInstruction.into())
    }

    #[inline(never)]
    fn handle_update_liquidation_fee_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        cranker_share_bps: u16,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if cranker_share_bps > 10_000 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.liquidation_cranker_fee_share_bps = cranker_share_bps;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_update_maintenance_fee_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        cranker_share_bps: u16,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if cranker_share_bps > 10_000 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.maintenance_cranker_fee_share_bps = cranker_share_bps;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    /// UpdateMaintenanceFeePerSlot (tag 88) — marketauth-gated.
    ///
    /// `maintenance_fee_per_slot` was an InitMarket constructor argument with
    /// no setter anywhere in the dispatch table, so it was frozen for the life
    /// of the market. This restores optionality only; the default stays 0 and
    /// nothing here enables the maintenance fee.
    ///
    /// Mirrors the marketauth idiom of the neighbouring single-field setters
    /// (`handle_update_maintenance_fee_policy`, `handle_update_fee_redirect_policy`):
    /// signer/writable/owner checks, load cfg via
    /// `read_market_config_mode_and_capacity`, gate on `cfg.marketauth` via
    /// `expect_live_authority`, mutate, write back. NOTE:
    /// `handle_update_trade_fee_policy` gates on asset-0's insurance authority
    /// instead, so despite the shared "fee policy" naming it is NOT the
    /// pattern to mirror here (same caveat as `handle_update_fee_split`).
    ///
    /// Range check mirrors InitMarket's: a setter must not be able to store a
    /// value InitMarket itself would reject.
    #[inline(never)]
    fn handle_update_maintenance_fee_per_slot<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        maintenance_fee_per_slot: u128,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if maintenance_fee_per_slot > percolator::MAX_PROTOCOL_FEE_ABS {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let (mut cfg, mode, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        // #428: gate on Live, mirroring handle_update_backing_fee_policy. Without this
        // the maintenance rate can be changed after the market has left Live, and a
        // permissionless crank then charges the new rate against account equity.
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.maintenance_fee_per_slot = maintenance_fee_per_slot;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_update_backing_fee_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        domain: u16,
        fee_bps: u16,
        insurance_share_bps: u16,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let domain = domain as usize;
        let asset_index = domain / 2;
        let (mut cfg, mode, _, _, max_trading_fee_bps) =
            state::read_market_trade_preflight(&market_ai.try_borrow_data()?, asset_index)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        {
            let market_data = market_ai.try_borrow_data()?;
            let profile = read_oracle_profile_for_asset(&market_data, &cfg, asset_index)?;
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
            expect_live_authority(&authorities.insurance_authority, authority.key)?;
        }
        if fee_bps > 10_000
            || insurance_share_bps > 10_000
            || (fee_bps == 0 && insurance_share_bps != 0)
            || fee_bps as u64 > max_trading_fee_bps
            || fee_bps as u64 > constants::MAX_DYNAMIC_TRADE_FEE_BPS
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // NOTE: the former `fee_split_floor_ok` two-rate check was retired
        // here (2026-07-19 fee-collection design). It validated a split of
        // `T = trade_fee_base_bps + backing_fee_bps` that no longer exists;
        // `validate_fee_split` (tag 86) now owns split validation. The shape
        // checks above (`max_trading_fee_bps`, `MAX_DYNAMIC_TRADE_FEE_BPS`,
        // the `fee_bps == 0 && insurance_share_bps != 0` guard) are unchanged.
        let long_side = domain % 2 == 0;
        let adjust_policy_count =
            |cfg: &mut WrapperConfigV16, old_fee: u16, new_fee: u16| -> ProgramResult {
                if old_fee == 0 && new_fee != 0 {
                    cfg.backing_trade_fee_policy_count = cfg
                        .backing_trade_fee_policy_count
                        .checked_add(1)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                } else if old_fee != 0 && new_fee == 0 {
                    cfg.backing_trade_fee_policy_count = cfg
                        .backing_trade_fee_policy_count
                        .checked_sub(1)
                        .ok_or(PercolatorError::EngineCounterUnderflow)?;
                }
                Ok(())
            };
        let mut market_data = market_ai.try_borrow_mut_data()?;
        {
            let (_cfg, group) = state::market_view_mut(&mut market_data)?;
            if asset_index >= group.markets.len() {
                return Err(PercolatorError::EngineLockActive.into());
            }
            let lifecycle = group.markets[asset_index].engine.asset.lifecycle;
            if lifecycle == ASSET_LIFECYCLE_RETIRED
                || (fee_bps != 0 && lifecycle != ASSET_LIFECYCLE_ACTIVE)
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
        }
        if asset_index == 0 {
            let mut profile = state::read_asset_oracle_profile(&market_data, asset_index)?;
            let old_fee = if long_side {
                cfg.backing_trade_fee_bps_long
            } else {
                cfg.backing_trade_fee_bps_short
            };
            adjust_policy_count(&mut cfg, old_fee, fee_bps)?;
            if long_side {
                cfg.backing_trade_fee_bps_long = fee_bps;
                cfg.backing_trade_fee_insurance_share_bps_long = insurance_share_bps;
                profile.backing_trade_fee_bps_long = fee_bps;
                profile.backing_trade_fee_insurance_share_bps_long = insurance_share_bps;
            } else {
                cfg.backing_trade_fee_bps_short = fee_bps;
                cfg.backing_trade_fee_insurance_share_bps_short = insurance_share_bps;
                profile.backing_trade_fee_bps_short = fee_bps;
                profile.backing_trade_fee_insurance_share_bps_short = insurance_share_bps;
            }
            state::write_wrapper_config(&mut market_data, &cfg)?;
            state::write_asset_oracle_profile(&mut market_data, asset_index, &profile)
        } else {
            let mut profile = state::read_asset_oracle_profile(&market_data, asset_index)?;
            let old_fee = if long_side {
                profile.backing_trade_fee_bps_long
            } else {
                profile.backing_trade_fee_bps_short
            };
            adjust_policy_count(&mut cfg, old_fee, fee_bps)?;
            if long_side {
                profile.backing_trade_fee_bps_long = fee_bps;
                profile.backing_trade_fee_insurance_share_bps_long = insurance_share_bps;
            } else {
                profile.backing_trade_fee_bps_short = fee_bps;
                profile.backing_trade_fee_insurance_share_bps_short = insurance_share_bps;
            }
            state::write_wrapper_config(&mut market_data, &cfg)?;
            state::write_asset_oracle_profile(&mut market_data, asset_index, &profile)
        }
    }

    #[inline(never)]
    fn handle_update_trade_fee_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        trade_fee_base_bps: u64,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let (mut cfg, asset0_insurance_authority, max_trading_fee_bps) = {
            let market_data = market_ai.try_borrow_data()?;
            let (cfg, _, _, _, max_trading_fee_bps) =
                state::read_market_trade_preflight(&market_data, 0)?;
            let profile0 = read_oracle_profile_for_asset(&market_data, &cfg, 0)?;
            (cfg, profile0.insurance_authority, max_trading_fee_bps)
        };
        expect_live_authority(&asset0_insurance_authority, authority.key)?;
        if trade_fee_base_bps > max_trading_fee_bps
            || trade_fee_base_bps > constants::MAX_DYNAMIC_TRADE_FEE_BPS
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // NOTE: the former `fee_split_floor_ok` scan over every configured
        // asset's stored long/short domains was retired here (2026-07-19
        // fee-collection design). It validated a split of
        // `T = trade_fee_base_bps + backing_fee_bps` that no longer exists;
        // `validate_fee_split` (tag 86) now owns split validation. The shape
        // checks above (`max_trading_fee_bps`, `MAX_DYNAMIC_TRADE_FEE_BPS`)
        // are unchanged. Removing the scan also makes this handler O(1)
        // again, retiring the W11 multi-asset-bypass concern along with the
        // check it guarded.
        cfg.trade_fee_base_bps = trade_fee_base_bps;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_update_fee_redirect_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        redirect_bps: u16,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if redirect_bps > 10_000 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.fee_redirect_to_market_0_bps = redirect_bps;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_update_market_init_fee_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        min_init_fee: u128,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let _ = amount_to_u64(min_init_fee)?;
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.permissionless_market_init_fee = min_init_fee;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    /// #427 — the missing writer for the insurance-withdrawal rate limit.
    ///
    /// `check_insurance_withdraw_cooldown` and `apply_insurance_withdraw_ceiling` are
    /// both correct and both no-ops while their policy fields are zero, and zero is the
    /// only value `handle_init_market` ever wrote. So #385, #386 and #396 were closed by
    /// adding enforcement that no deployed market could reach. Upstream carries the same
    /// two fields with the same single `: 0,` write and no setter either, so there is no
    /// upstream implementation to port — this diverges deliberately.
    ///
    /// `deposits_only` is a flag (any non-zero arms the deposits-only ceiling), so it
    /// needs no bound. `cooldown_slots` is a duration and therefore does — see
    /// `MAX_INSURANCE_WITHDRAW_COOLDOWN_SLOTS`. Zero remains legal for both: it is how a
    /// market turns the limit back OFF, and refusing it would make the policy one-way.
    #[inline(never)]
    fn handle_update_insurance_withdraw_policy<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        deposits_only: u8,
        cooldown_slots: u64,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if cooldown_slots > constants::MAX_INSURANCE_WITHDRAW_COOLDOWN_SLOTS {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (mut cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        cfg.insurance_withdraw_deposits_only = deposits_only;
        cfg.insurance_withdraw_cooldown_slots = cooldown_slots;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_configure_permissionless_resolve<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        stale_slots: u64,
        force_close_delay_slots: u64,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if stale_slots < constants::MIN_PERMISSIONLESS_RESOLVE_STALE_SLOTS
            || stale_slots > constants::MAX_PERMISSIONLESS_RESOLVE_STALE_SLOTS
            || force_close_delay_slots == 0
            || force_close_delay_slots > constants::MAX_FORCE_CLOSE_DELAY_SLOTS
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (mut cfg, mode, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        expect_live_authority(&cfg.marketauth, admin.key)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if oracle_v16::permissionless_stale_matured(&cfg, authenticated_slot_or_fallback(0)) {
            return Err(PercolatorError::OracleStale.into());
        }
        cfg.permissionless_resolve_stale_slots = stale_slots;
        cfg.force_close_delay_slots = force_close_delay_slots;
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg)
    }

    #[inline(never)]
    fn handle_resolve_stale_permissionless<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        now_slot: u64,
    ) -> ProgramResult {
        let market_ai = account(accounts, 0)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
        if group.header.mode != 0 {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if authenticated_slot < group.header.current_slot.get() {
            return Err(PercolatorError::EngineStale.into());
        }
        if !oracle_v16::permissionless_stale_matured(&cfg, authenticated_slot) {
            return Err(PercolatorError::OracleStale.into());
        }
        group
            .resolve_market_not_atomic(authenticated_slot)
            .map_err(map_v16_error)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn handle_configure_hybrid_oracle<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        now_unix_ts: i64,
        oracle_leg_count: u8,
        oracle_leg_flags: u8,
        max_staleness_secs: u64,
        hybrid_soft_stale_slots: u64,
        mark_ewma_halflife_slots: u64,
        mark_min_fee: u64,
        invert: u8,
        unit_scale: u32,
        conf_filter_bps: u16,
        oracle_leg_feeds: [[u8; 32]; constants::ORACLE_LEG_CAP],
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if oracle_leg_count == 0
            || oracle_leg_count as usize > constants::ORACLE_LEG_CAP
            || !oracle_v16::oracle_leg_config_ok(
                oracle_leg_count,
                oracle_leg_flags,
                &oracle_leg_feeds,
            )
            || max_staleness_secs == 0
            || hybrid_soft_stale_slots == 0
            || invert > 1
            // B-11: cap oracle staleness at MAX_ORACLE_STALENESS_SECS (86400 s = 1 day).
            // A stale-price oracle that never forces the hybrid into soft-stale is an
            // economic attack surface; capping at 1 day is the minimum safe upper-bound.
            || max_staleness_secs > constants::MAX_ORACLE_STALENESS_SECS
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let oracle_accounts = accounts
            .get(2..2 + oracle_leg_count as usize)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let authenticated_unix_ts = Clock::get()
            .map(|c| c.unix_timestamp)
            .unwrap_or(now_unix_ts);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            if authenticated_slot < group.header.current_slot.get() {
                return Err(PercolatorError::EngineStale.into());
            }
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_asset_active_for_oracle_reconfiguration_view(&group, asset_index_usize)?;
            let existing_profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            // Asset 0 has a real stored profile; gate oracle reconfiguration on its
            // oracle_authority exactly like permissionless assets 1..N.
            expect_live_authority(&existing_profile.oracle_authority, admin.key)?;

            let mut profile = state::AssetOracleProfileV16 {
                oracle_mode: constants::ORACLE_MODE_HYBRID_AFTER_HOURS,
                oracle_leg_count,
                oracle_leg_flags,
                invert,
                unit_scale,
                conf_filter_bps,
                backing_trade_fee_bps_long: existing_profile.backing_trade_fee_bps_long,
                backing_trade_fee_bps_short: existing_profile.backing_trade_fee_bps_short,
                backing_trade_fee_insurance_share_bps_long: existing_profile
                    .backing_trade_fee_insurance_share_bps_long,
                backing_trade_fee_insurance_share_bps_short: existing_profile
                    .backing_trade_fee_insurance_share_bps_short,
                _padding0: [0u8; 6],
                insurance_authority: existing_profile.insurance_authority,
                insurance_operator: existing_profile.insurance_operator,
                asset_admin: existing_profile.asset_admin,
                backing_bucket_authority: existing_profile.backing_bucket_authority,
                oracle_authority: existing_profile.oracle_authority,
                max_staleness_secs,
                hybrid_soft_stale_slots,
                mark_ewma_e6: 0,
                mark_ewma_last_slot: 0,
                mark_ewma_halflife_slots,
                mark_min_fee,
                oracle_target_price_e6: 0,
                oracle_target_publish_time: 0,
                last_good_oracle_slot: 0,
                oracle_leg_feeds,
                oracle_leg_prices_e6: [0u64; constants::ORACLE_LEG_CAP],
                oracle_leg_publish_times: [0i64; constants::ORACLE_LEG_CAP],
            };

            let (price, publish_time, advanced) = oracle_v16::read_external_price_e6_profile(
                &mut profile,
                oracle_accounts,
                authenticated_unix_ts,
            )?;
            if !advanced || price == 0 {
                return Err(PercolatorError::OracleInvalid.into());
            }
            profile.last_good_oracle_slot = authenticated_slot;
            profile.oracle_target_price_e6 = price;
            profile.oracle_target_publish_time = publish_time;
            profile.mark_ewma_e6 = price;
            profile.mark_ewma_last_slot = authenticated_slot;
            group
                .reset_empty_asset_oracle_anchor_not_atomic(
                    asset_index_usize,
                    price,
                    authenticated_slot,
                )
                .map_err(map_v16_error)?;
            cfg.last_good_oracle_slot =
                core::cmp::max(cfg.last_good_oracle_slot, authenticated_slot);
            write_oracle_profile_to_view(&mut group, asset_index_usize, &profile)?;
            if asset_index_usize == 0 {
                cfg.oracle_mode = profile.oracle_mode;
                cfg.oracle_leg_count = profile.oracle_leg_count;
                cfg.oracle_leg_flags = profile.oracle_leg_flags;
                cfg.invert = profile.invert;
                cfg.unit_scale = profile.unit_scale;
                cfg.conf_filter_bps = profile.conf_filter_bps;
                cfg.max_staleness_secs = profile.max_staleness_secs;
                cfg.hybrid_soft_stale_slots = profile.hybrid_soft_stale_slots;
                cfg.mark_ewma_halflife_slots = profile.mark_ewma_halflife_slots;
                cfg.mark_min_fee = profile.mark_min_fee;
                cfg.oracle_leg_feeds = profile.oracle_leg_feeds;
                cfg.oracle_leg_prices_e6 = profile.oracle_leg_prices_e6;
                cfg.oracle_leg_publish_times = profile.oracle_leg_publish_times;
                cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = profile.oracle_target_publish_time;
                cfg.mark_ewma_e6 = profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_configure_ewma_mark<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        initial_mark_e6: u64,
        mark_ewma_halflife_slots: u64,
        mark_min_fee: u64,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(admin)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if initial_mark_e6 == 0
            || initial_mark_e6 > percolator::MAX_ORACLE_PRICE
            || mark_ewma_halflife_slots == 0
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            if authenticated_slot < group.header.current_slot.get() {
                return Err(PercolatorError::EngineStale.into());
            }
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_asset_active_for_oracle_reconfiguration_view(&group, asset_index_usize)?;
            let existing_profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            // Asset 0 has a real stored profile; gate oracle reconfiguration on its
            // oracle_authority exactly like permissionless assets 1..N.
            expect_live_authority(&existing_profile.oracle_authority, admin.key)?;

            let profile = state::AssetOracleProfileV16 {
                oracle_mode: constants::ORACLE_MODE_EWMA_MARK,
                oracle_leg_count: 0,
                oracle_leg_flags: 0,
                invert: 0,
                unit_scale: 0,
                conf_filter_bps: 0,
                backing_trade_fee_bps_long: existing_profile.backing_trade_fee_bps_long,
                backing_trade_fee_bps_short: existing_profile.backing_trade_fee_bps_short,
                backing_trade_fee_insurance_share_bps_long: existing_profile
                    .backing_trade_fee_insurance_share_bps_long,
                backing_trade_fee_insurance_share_bps_short: existing_profile
                    .backing_trade_fee_insurance_share_bps_short,
                _padding0: [0u8; 6],
                insurance_authority: existing_profile.insurance_authority,
                insurance_operator: existing_profile.insurance_operator,
                asset_admin: existing_profile.asset_admin,
                backing_bucket_authority: existing_profile.backing_bucket_authority,
                oracle_authority: existing_profile.oracle_authority,
                max_staleness_secs: 0,
                hybrid_soft_stale_slots: 0,
                mark_ewma_e6: initial_mark_e6,
                mark_ewma_last_slot: authenticated_slot,
                mark_ewma_halflife_slots,
                mark_min_fee,
                oracle_target_price_e6: initial_mark_e6,
                oracle_target_publish_time: 0,
                last_good_oracle_slot: authenticated_slot,
                oracle_leg_feeds: [[0u8; 32]; constants::ORACLE_LEG_CAP],
                oracle_leg_prices_e6: [0u64; constants::ORACLE_LEG_CAP],
                oracle_leg_publish_times: [0i64; constants::ORACLE_LEG_CAP],
            };

            group
                .reset_empty_asset_oracle_anchor_not_atomic(
                    asset_index_usize,
                    initial_mark_e6,
                    authenticated_slot,
                )
                .map_err(map_v16_error)?;
            cfg.last_good_oracle_slot =
                core::cmp::max(cfg.last_good_oracle_slot, authenticated_slot);
            write_oracle_profile_to_view(&mut group, asset_index_usize, &profile)?;
            if asset_index_usize == 0 {
                cfg.oracle_mode = profile.oracle_mode;
                cfg.oracle_leg_count = 0;
                cfg.oracle_leg_flags = 0;
                cfg.invert = 0;
                cfg.unit_scale = 0;
                cfg.conf_filter_bps = 0;
                cfg.max_staleness_secs = 0;
                cfg.hybrid_soft_stale_slots = 0;
                cfg.mark_ewma_e6 = profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
                cfg.mark_ewma_halflife_slots = profile.mark_ewma_halflife_slots;
                cfg.mark_min_fee = profile.mark_min_fee;
                cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = 0;
                cfg.oracle_leg_feeds = [[0u8; 32]; constants::ORACLE_LEG_CAP];
                cfg.oracle_leg_prices_e6 = [0u64; constants::ORACLE_LEG_CAP];
                cfg.oracle_leg_publish_times = [0i64; constants::ORACLE_LEG_CAP];
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_configure_auth_mark<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        initial_mark_e6: u64,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if initial_mark_e6 == 0 || initial_mark_e6 > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            if authenticated_slot < group.header.current_slot.get() {
                return Err(PercolatorError::EngineStale.into());
            }
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_asset_active_for_oracle_reconfiguration_view(&group, asset_index_usize)?;
            let existing_profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            // Asset 0 has a real stored profile; gate oracle reconfiguration on its
            // oracle_authority exactly like permissionless assets 1..N.
            expect_live_authority(&existing_profile.oracle_authority, authority.key)?;

            let profile = state::AssetOracleProfileV16 {
                oracle_mode: constants::ORACLE_MODE_AUTH_MARK,
                oracle_leg_count: 0,
                oracle_leg_flags: 0,
                invert: 0,
                unit_scale: 0,
                conf_filter_bps: 0,
                backing_trade_fee_bps_long: existing_profile.backing_trade_fee_bps_long,
                backing_trade_fee_bps_short: existing_profile.backing_trade_fee_bps_short,
                backing_trade_fee_insurance_share_bps_long: existing_profile
                    .backing_trade_fee_insurance_share_bps_long,
                backing_trade_fee_insurance_share_bps_short: existing_profile
                    .backing_trade_fee_insurance_share_bps_short,
                _padding0: [0u8; 6],
                insurance_authority: existing_profile.insurance_authority,
                insurance_operator: existing_profile.insurance_operator,
                asset_admin: existing_profile.asset_admin,
                backing_bucket_authority: existing_profile.backing_bucket_authority,
                oracle_authority: existing_profile.oracle_authority,
                max_staleness_secs: 0,
                hybrid_soft_stale_slots: 0,
                mark_ewma_e6: initial_mark_e6,
                mark_ewma_last_slot: authenticated_slot,
                mark_ewma_halflife_slots: 0,
                mark_min_fee: 0,
                oracle_target_price_e6: initial_mark_e6,
                oracle_target_publish_time: 0,
                last_good_oracle_slot: authenticated_slot,
                oracle_leg_feeds: [[0u8; 32]; constants::ORACLE_LEG_CAP],
                oracle_leg_prices_e6: [0u64; constants::ORACLE_LEG_CAP],
                oracle_leg_publish_times: [0i64; constants::ORACLE_LEG_CAP],
            };

            group
                .reset_empty_asset_oracle_anchor_not_atomic(
                    asset_index_usize,
                    initial_mark_e6,
                    authenticated_slot,
                )
                .map_err(map_v16_error)?;
            cfg.last_good_oracle_slot =
                core::cmp::max(cfg.last_good_oracle_slot, authenticated_slot);
            // Asset 0 now carries a real stored profile: persist it like 1..N, and ALSO mirror the
            // oracle/mark fields into the market-wide config (other code paths still read cfg for asset 0).
            write_oracle_profile_to_view(&mut group, asset_index_usize, &profile)?;
            if asset_index_usize == 0 {
                cfg.oracle_mode = profile.oracle_mode;
                cfg.oracle_leg_count = 0;
                cfg.oracle_leg_flags = 0;
                cfg.invert = 0;
                cfg.unit_scale = 0;
                cfg.conf_filter_bps = 0;
                cfg.max_staleness_secs = 0;
                cfg.hybrid_soft_stale_slots = 0;
                cfg.mark_ewma_e6 = profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
                cfg.mark_ewma_halflife_slots = 0;
                cfg.mark_min_fee = 0;
                cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = 0;
                cfg.oracle_leg_feeds = [[0u8; 32]; constants::ORACLE_LEG_CAP];
                cfg.oracle_leg_prices_e6 = [0u64; constants::ORACLE_LEG_CAP];
                cfg.oracle_leg_publish_times = [0i64; constants::ORACLE_LEG_CAP];
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_push_ewma_mark<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        mark_e6: u64,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if mark_e6 == 0 || mark_e6 > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let mut profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_asset_mark_pushable_view(&group, asset_index_usize)?;
            if !oracle_v16::profile_is_ewma_mark(&profile) {
                return Err(PercolatorError::Unauthorized.into());
            }
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index_usize);
            expect_live_authority(&authorities.oracle_authority, authority.key)?;
            if authenticated_slot < profile.mark_ewma_last_slot
                || authenticated_slot < group.header.current_slot.get()
            {
                return Err(PercolatorError::EngineStale.into());
            }
            let full_weight_fee = if profile.mark_min_fee == 0 {
                0
            } else {
                profile.mark_min_fee
            };
            let next_mark = policy_v16::ewma_update(
                profile.mark_ewma_e6,
                mark_e6,
                profile.mark_ewma_halflife_slots,
                profile.mark_ewma_last_slot,
                authenticated_slot,
                full_weight_fee,
                profile.mark_min_fee,
            );
            if next_mark == 0 || next_mark > percolator::MAX_ORACLE_PRICE {
                return Err(PercolatorError::OracleInvalid.into());
            }
            profile.mark_ewma_e6 = next_mark;
            profile.mark_ewma_last_slot = authenticated_slot;
            profile.oracle_target_price_e6 = next_mark;
            profile.oracle_target_publish_time = 0;
            profile.last_good_oracle_slot = authenticated_slot;
            cfg.last_good_oracle_slot =
                core::cmp::max(cfg.last_good_oracle_slot, authenticated_slot);
            write_oracle_profile_to_view(&mut group, asset_index_usize, &profile)?;
            if asset_index_usize == 0 {
                cfg.mark_ewma_e6 = profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
                cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = 0;
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_push_auth_mark<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        asset_index: u16,
        now_slot: u64,
        mark_e6: u64,
    ) -> ProgramResult {
        let authority = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        expect_signer(authority)?;
        expect_writable(market_ai)?;
        expect_owner(market_ai, program_id)?;
        if mark_e6 == 0 || mark_e6 > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let asset_index_usize = asset_index as usize;
        let authenticated_slot = authenticated_slot_or_fallback(now_slot);
        let cfg_after = {
            let mut data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let mut profile = read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            require_asset_mark_pushable_view(&group, asset_index_usize)?;
            if !oracle_v16::profile_is_auth_mark(&profile) {
                return Err(PercolatorError::Unauthorized.into());
            }
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index_usize);
            expect_live_authority(&authorities.oracle_authority, authority.key)?;
            if authenticated_slot < profile.mark_ewma_last_slot
                || authenticated_slot < group.header.current_slot.get()
            {
                return Err(PercolatorError::EngineStale.into());
            }
            profile.mark_ewma_e6 = mark_e6;
            profile.mark_ewma_last_slot = authenticated_slot;
            profile.oracle_target_price_e6 = mark_e6;
            profile.oracle_target_publish_time = 0;
            profile.last_good_oracle_slot = authenticated_slot;
            cfg.last_good_oracle_slot =
                core::cmp::max(cfg.last_good_oracle_slot, authenticated_slot);
            write_oracle_profile_to_view(&mut group, asset_index_usize, &profile)?;
            if asset_index_usize == 0 {
                cfg.mark_ewma_e6 = profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = profile.mark_ewma_last_slot;
                cfg.mark_ewma_halflife_slots = 0;
                cfg.mark_min_fee = 0;
                cfg.oracle_target_price_e6 = profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = 0;
            }
            group.validate_shape().map_err(map_v16_error)?;
            cfg
        };
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)
    }

    #[inline(never)]
    fn handle_close_resolved<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        _fee_rate_per_slot: u128,
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;

        let (cfg_after, payout) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let max_market_slots = group.header.config.max_market_slots.get() as usize;
            ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            // E2: owner==signer OR signer holds the bound NFT (escrowed). NFT trio at base 7.
            let nft = optional_nft_holder_accounts(accounts, 7);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
            if group.header.mode != 1 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            if cfg.force_close_delay_slots != 0
                && authenticated_market_slot_or_fallback_view(&group)
                    .saturating_sub(group.header.resolved_slot.get())
                    < cfg.force_close_delay_slots
            {
                expect_signer(owner)?;
            }
            let insurance_before = group.header.insurance.get();
            let outcome = group
                .close_resolved_account_not_atomic(&mut portfolio, cfg.maintenance_fee_per_slot)
                .map_err(map_v16_error)?;
            // close_resolved can charge an accrued maintenance fee into header.insurance.
            // Domain-credit it (mirroring SyncMaintenanceFee) so it stays withdrawable via
            // a per-domain budget; otherwise it strands in aggregate insurance — withdrawable
            // by nobody — and permanently bricks CloseSlab (Finding G).
            let retained = group
                .header
                .insurance
                .get()
                .saturating_sub(insurance_before);
            credit_maintenance_fee_to_active_market_budgets_view(&cfg, &mut group, retained)?;
            group.validate_shape().map_err(map_v16_error)?;
            let payout = match outcome {
                percolator::ResolvedCloseOutcomeV16::ProgressOnly => 0,
                percolator::ResolvedCloseOutcomeV16::Closed { payout } => payout,
            };
            (cfg, payout)
        };
        if payout != 0 {
            let dest_token = account(accounts, 3)?;
            let vault_token = account(accounts, 4)?;
            let vault_authority_ai = account(accounts, 5)?;
            let token_program = account(accounts, 6)?;
            expect_writable(dest_token)?;
            expect_writable(vault_token)?;
            verify_token_program(token_program)?;
            let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
            expect_key(vault_authority_ai, &vault_authority)?;
            verify_withdrawable_token_accounts(
                dest_token,
                owner.key,
                vault_token,
                &vault_authority,
                &cfg_after,
            )?;
            verify_permissionless_payout_dest_token_account(dest_token)?;
            let payout_u64 = amount_to_u64(payout)?;
            require_token_balance(vault_token, payout_u64)?;
            let bump_arr = [bump];
            let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
            transfer_tokens_signed(
                token_program,
                vault_token,
                dest_token,
                vault_authority_ai,
                payout_u64,
                signer_seeds,
            )?;
        }
        Ok(())
    }

    #[inline(never)]
    fn handle_claim_resolved_payout_topup<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;

        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        let (cfg, payout) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            // E2: owner==signer OR signer holds the bound NFT (escrowed). NFT trio at base 7.
            let nft = optional_nft_holder_accounts(accounts, 7);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
            let payout = group
                .claim_resolved_payout_topup_not_atomic(&mut portfolio)
                .map_err(map_v16_error)?;
            (cfg, payout)
        };
        if payout != 0 {
            let dest_token = account(accounts, 3)?;
            let vault_token = account(accounts, 4)?;
            let vault_authority_ai = account(accounts, 5)?;
            let token_program = account(accounts, 6)?;
            expect_writable(dest_token)?;
            expect_writable(vault_token)?;
            verify_token_program(token_program)?;
            let (vault_authority, bump) = derive_vault_authority(program_id, market_ai.key);
            expect_key(vault_authority_ai, &vault_authority)?;
            verify_withdrawable_token_accounts(
                dest_token,
                owner.key,
                vault_token,
                &vault_authority,
                &cfg,
            )?;
            verify_permissionless_payout_dest_token_account(dest_token)?;
            let payout_u64 = amount_to_u64(payout)?;
            require_token_balance(vault_token, payout_u64)?;
            let bump_arr = [bump];
            let signer_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &bump_arr]];
            transfer_tokens_signed(
                token_program,
                vault_token,
                dest_token,
                vault_authority_ai,
                payout_u64,
                signer_seeds,
            )?;
        }
        let _ = cfg;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn handle_permissionless_crank_zero_copy<'a>(
        program_id: &Pubkey,
        owner: &AccountInfo<'a>,
        market_ai: &AccountInfo<'a>,
        portfolio_ai: &AccountInfo<'a>,
        tail: &[AccountInfo<'a>],
        action: u8,
        asset_index: u16,
        now_slot: u64,
        funding_rate_e9: i128,
        recovery_reason: u8,
        max_market_slots: usize,
    ) -> ProgramResult {
        if funding_rate_e9 != 0 || recovery_reason != 0 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if action > 2 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        let authenticated_now_slot = authenticated_slot_or_fallback(now_slot);
        let asset_index_usize = asset_index as usize;
        let cfg_after;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            if asset_index_usize >= group.header.config.max_market_slots.get() as usize {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let crank_action = match action {
                0 => PermissionlessCrankActionV16::Refresh,
                // FIX W3 (upstream #206, pairs with engine E3 / #92): close_q and
                // fee_bps are no longer caller-supplied -- the engine selects the
                // liquidation size (liquidation_engine_close_request_q) and always
                // reads the fee rate from config inside liquidate_account_not_atomic.
                1 => PermissionlessCrankActionV16::Liquidate(percolator::LiquidationRequestV16 {
                    asset_index: asset_index_usize,
                }),
                2 => PermissionlessCrankActionV16::SettleB {
                    asset_index: asset_index_usize,
                },
                _ => return Err(PercolatorError::InvalidInstruction.into()),
            };
            let mut oracle_profile =
                read_oracle_profile_from_view(&group, &cfg, asset_index_usize)?;
            let now_unix_ts = Clock::get().map(|c| c.unix_timestamp).unwrap_or_else(|_| {
                let elapsed_slots =
                    authenticated_now_slot.saturating_sub(oracle_profile.last_good_oracle_slot);
                oracle_profile
                    .oracle_target_publish_time
                    .saturating_add(i64::try_from(elapsed_slots).unwrap_or(i64::MAX))
            });
            let reward_enabled = action == 1 && cfg.liquidation_cranker_fee_share_bps != 0;
            let mut oracle_tail = tail;
            let mut cranker_portfolio_ai = None;
            if reward_enabled {
                if let Some((last, rest)) = tail.split_last() {
                    if last.owner == program_id {
                        expect_signer(owner)?;
                        expect_writable(last)?;
                        if last.key == portfolio_ai.key {
                            return Err(PercolatorError::InvalidInstruction.into());
                        }
                        ensure_portfolio_storage_for_market_slots(last, max_market_slots)?;
                        cranker_portfolio_ai = Some(last);
                        oracle_tail = rest;
                    }
                }
            }
            reject_permissionless_resolve_matured_live_for_profile_view(
                &cfg,
                &oracle_profile,
                &group,
            )?;
            let crank_price = hybrid_effective_price_for_crank_view(
                &cfg,
                &mut oracle_profile,
                &group,
                asset_index_usize,
                authenticated_now_slot,
                now_unix_ts,
                oracle_tail,
            )?;
            let computed_funding_rate_e9 = permissionless_funding_rate_e9_view(
                &oracle_profile,
                &group,
                asset_index_usize,
                crank_price,
            )?;
            group
                .set_asset_raw_oracle_target_not_atomic(
                    asset_index_usize,
                    oracle_profile.oracle_target_price_e6,
                )
                .map_err(map_v16_error)?;
            cfg.last_good_oracle_slot = core::cmp::max(
                cfg.last_good_oracle_slot,
                oracle_profile.last_good_oracle_slot,
            );
            write_oracle_profile_to_view(&mut group, asset_index_usize, &oracle_profile)?;
            if asset_index_usize == 0 && oracle_v16::profile_is_price_managed(&oracle_profile) {
                cfg.oracle_mode = oracle_profile.oracle_mode;
                cfg.oracle_leg_count = oracle_profile.oracle_leg_count;
                cfg.oracle_leg_flags = oracle_profile.oracle_leg_flags;
                cfg.invert = oracle_profile.invert;
                cfg.unit_scale = oracle_profile.unit_scale;
                cfg.conf_filter_bps = oracle_profile.conf_filter_bps;
                cfg.max_staleness_secs = oracle_profile.max_staleness_secs;
                cfg.hybrid_soft_stale_slots = oracle_profile.hybrid_soft_stale_slots;
                cfg.mark_ewma_e6 = oracle_profile.mark_ewma_e6;
                cfg.mark_ewma_last_slot = oracle_profile.mark_ewma_last_slot;
                cfg.mark_ewma_halflife_slots = oracle_profile.mark_ewma_halflife_slots;
                cfg.mark_min_fee = oracle_profile.mark_min_fee;
                cfg.oracle_target_price_e6 = oracle_profile.oracle_target_price_e6;
                cfg.oracle_target_publish_time = oracle_profile.oracle_target_publish_time;
                cfg.oracle_leg_feeds = oracle_profile.oracle_leg_feeds;
                cfg.oracle_leg_prices_e6 = oracle_profile.oracle_leg_prices_e6;
                cfg.oracle_leg_publish_times = oracle_profile.oracle_leg_publish_times;
            }

            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            let mut portfolio =
                state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
            expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
            let insurance_before = group.header.insurance.get();
            let is_liquidation = matches!(crank_action, PermissionlessCrankActionV16::Liquidate(_));
            if let Some(cranker_ai) = cranker_portfolio_ai {
                let mut cranker_data = cranker_ai.try_borrow_mut_data()?;
                let mut cranker = state::portfolio_view_mut_for_market_slots(
                    &mut cranker_data,
                    max_market_slots,
                )?;
                expect_portfolio_view_account_key(&cranker, cranker_ai.key)?;
                expect_portfolio_view_owner(&cranker, owner.key)?;
                cranker
                    .validate_with_market(&group.as_view())
                    .map_err(map_v16_error)?;
                if let PermissionlessCrankActionV16::Liquidate(liq) = crank_action {
                    group
                        .accrue_asset_to_not_atomic(
                            asset_index_usize,
                            authenticated_now_slot,
                            crank_price,
                            computed_funding_rate_e9,
                            true,
                        )
                        .map_err(map_v16_error)?;
                    group
                        .liquidate_account_not_atomic(&mut portfolio, liq)
                        .map_err(map_v16_error)?;
                } else {
                    group
                        .permissionless_crank_not_atomic(
                            &mut portfolio,
                            PermissionlessCrankRequestV16 {
                                now_slot: authenticated_now_slot,
                                asset_index: asset_index_usize,
                                effective_price: crank_price,
                                funding_rate_e9: computed_funding_rate_e9,
                                action: crank_action,
                            },
                        )
                        .map_err(map_v16_error)?;
                }
                let retained_fee = group
                    .header
                    .insurance
                    .get()
                    .saturating_sub(insurance_before);
                let reward = maintenance_cranker_reward(retained_fee, cfg.liquidation_cranker_fee_share_bps)?;
                let reward = core::cmp::min(reward, retained_fee);
                if reward != 0 {
                    // Protocol-fee RESERVE amendment: same reservation
                    // threading as SyncMaintenanceFee above -- this
                    // permissionless-crank/liquidation reward must not be
                    // able to dip insurance below the protocol's
                    // accrued-but-unwithdrawn claim.
                    //
                    // The LP leg is deliberately NOT reserved here -- see the
                    // `SyncMaintenanceFee` site above for why (this reward is
                    // `engine_available`-neutral, and reserving LP fees against
                    // `credit_account_from_insurance_not_atomic` would make them
                    // senior to loss coverage).
                    let protocol_owed = cfg
                        .protocol_fee_accrued_atoms
                        .saturating_sub(cfg.protocol_fee_withdrawn_atoms);
                    group
                        .credit_account_from_insurance_not_atomic(
                            &mut cranker,
                            reward,
                            protocol_owed,
                        )
                        .map_err(map_v16_error)?;
                }
                let retained_after_reward = retained_fee
                    .checked_sub(reward)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                credit_market_fee_split_across_domains_view(
                    &cfg,
                    &mut group,
                    asset_index_usize,
                    retained_after_reward,
                )?;
                group.validate_shape().map_err(map_v16_error)?;
                cranker
                    .validate_with_market(&group.as_view())
                    .map_err(map_v16_error)?;
            } else {
                if let PermissionlessCrankActionV16::Liquidate(liq) = crank_action {
                    group
                        .accrue_asset_to_not_atomic(
                            asset_index_usize,
                            authenticated_now_slot,
                            crank_price,
                            computed_funding_rate_e9,
                            true,
                        )
                        .map_err(map_v16_error)?;
                    group
                        .liquidate_account_not_atomic(&mut portfolio, liq)
                        .map_err(map_v16_error)?;
                } else {
                    group
                        .permissionless_crank_not_atomic(
                            &mut portfolio,
                            PermissionlessCrankRequestV16 {
                                now_slot: authenticated_now_slot,
                                asset_index: asset_index_usize,
                                effective_price: crank_price,
                                funding_rate_e9: computed_funding_rate_e9,
                                action: crank_action,
                            },
                        )
                        .map_err(map_v16_error)?;
                }
                let retained_fee = group
                    .header
                    .insurance
                    .get()
                    .saturating_sub(insurance_before);
                credit_market_fee_split_across_domains_view(
                    &cfg,
                    &mut group,
                    asset_index_usize,
                    retained_fee,
                )?;
                if is_liquidation {
                    group.validate_shape().map_err(map_v16_error)?;
                }
            }
            cfg_after = cfg;
        }
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn handle_permissionless_crank<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        action: u8,
        asset_index: u16,
        now_slot: u64,
        funding_rate_e9: i128,
        recovery_reason: u8,
    ) -> ProgramResult {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        handle_permissionless_crank_zero_copy(
            program_id,
            owner,
            market_ai,
            portfolio_ai,
            accounts.get(3..).unwrap_or(&[]),
            action,
            asset_index,
            now_slot,
            funding_rate_e9,
            recovery_reason,
            max_market_slots,
        )
    }

    // ── Fork LP Vault handlers (tags 74-80) ─────────────────────────────────
    //
    // All handlers below are v17-adapted ports of the original fork's LP vault
    // (originally tags 65-71). Key adaptations vs the original fork:
    //   - `cfg.admin`  →  `cfg.marketauth`  (auth overhaul)
    //   - u64 LP shares  →  u128 LP shares (LpRedemptionV16.shares is u128)
    //   - percolator::wide_math re-exported via fork-facade for U256 arithmetic
    //   - add_fresh_counterparty_backing_view uses EngineCounterOverflow not
    //     EngineArithmeticOverflow for counter-bump errors (matching v17 engine)
    //
    // Helper functions (source_credit_available_backing_num,
    // expected_source_credit_rate_num, add_fresh_counterparty_backing_view,
    // backing_domain_parts_view, sync_backing_domain_ledger,
    // read_or_new_backing_domain_ledger, write_or_init_backing_domain_ledger)
    // are defined after the handlers below.

    /// LP Vault — CreateLpVault (tag 74).
    ///
    /// Creates the registry PDA + SPL LP-share mint PDA for a market's LP vault.
    /// marketauth-gated. Domain must be within the market's configured range.
    #[inline(never)]
    fn handle_create_lp_vault<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        fee_share_bps: u16,
        redemption_cooldown_slots: u64,
        oi_reservation_threshold_bps: u16,
        domain: u16,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let mint_ai = account(accounts, 3)?;
        let system_program_ai = account(accounts, 4)?;
        let token_program = account(accounts, 5)?;

        expect_signer(admin)?;
        expect_writable(admin)?;
        expect_writable(market_ai)?;
        expect_writable(registry_ai)?;
        expect_writable(mint_ai)?;
        expect_owner(market_ai, program_id)?;
        verify_token_program(token_program)?;
        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if fee_share_bps > 10_000 || oi_reservation_threshold_bps > 10_000 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // #440: `redemption_cooldown_slots` sat here as a raw u64 beside two bounded
        // parameters. It is written exactly once (below, the ONLY write in the program)
        // and read only at ExecuteRedemption, so an absurd value can never be lowered and
        // permanently strands every depositor's principal — CloseLpVault cannot unwind it
        // because only the blocked redemption burns shares. Bound it at creation, which is
        // the only place a bound can exist. See MAX_LP_REDEMPTION_COOLDOWN_SLOTS for why
        // this matches percolator-stake's cap exactly and why 0 stays legal here.
        if redemption_cooldown_slots > crate::constants::MAX_LP_REDEMPTION_COOLDOWN_SLOTS {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        // marketauth gate + domain bound (v17: cfg.marketauth replaces cfg.admin).
        let (cfg, mode, configured_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if admin.key.to_bytes() != cfg.marketauth {
            return Err(PercolatorError::Unauthorized.into());
        }
        if (domain as usize) >= configured_slots.saturating_mul(2) {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // REACHABILITY, not just range. The check above bounds `domain`; it says nothing about
        // whether the vault created there could ever function. If that domain's backing bucket
        // is already funded at a FOREIGN expiry, the vault is born dead: the FIND-1 binding
        // below hands `backing_bucket_authority` to the registry PDA, DepositToLpVault then
        // refuses for the whole term because the bucket's expiry is not
        // LP_VAULT_BACKING_EXPIRY_SLOT, and the provider who funded the bucket can no longer
        // withdraw because the authority they held is gone. The only exit is CloseLpVault,
        // which permanently forfeits this market's ability to ever have an LP vault.
        //
        // Checked BEFORE the authority is taken, so a refusal leaves the bucket's owner intact.
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (_cfg_r, group) = state::market_view_mut(&mut market_data)?;
            let (_, bucket) = backing_domain_parts_view(&group, domain as usize)?;
            let already_funded = bucket.status != percolator::BackingBucketStatusV16::Empty
                || bucket.fresh_unliened_backing_num > 0;
            if already_funded
                && bucket.expiry_slot != crate::constants::LP_VAULT_BACKING_EXPIRY_SLOT
            {
                return Err(PercolatorError::LpVaultBackingBucketNotEmpty.into());
            }
        }

        // Derive + bind the two PDAs.
        let (registry_pda, registry_bump) =
            state::derive_lp_vault_registry(program_id, market_ai.key);
        expect_key(registry_ai, &registry_pda)?;
        let (mint_pda, mint_bump) = state::derive_lp_vault_mint(program_id, market_ai.key);
        expect_key(mint_ai, &mint_pda)?;

        // Both PDAs must be fresh (system-owned, no data) — fail closed otherwise.
        if registry_ai.owner != &system_program::ID
            || mint_ai.owner != &system_program::ID
            || !registry_ai.data_is_empty()
            || !mint_ai.data_is_empty()
        {
            return Err(PercolatorError::AlreadyInitialized.into());
        }

        // FIND-1 fix: bind the registry PDA as the vault domain's backing-bucket
        // authority *here*, atomically with vault creation. DepositToLpVault
        // (tag 75) requires `backing_bucket_authority == registry_pda` for the
        // asset (see domain_authorities_from_profile), but the registry PDA can
        // never co-sign an UpdateAssetAuthority (tag 65) rotation from a client
        // (the non-zero incoming authority must sign to prove control) — so that
        // path is permanently unreachable. Writing it directly during
        // CreateLpVault is the only way to reach a working state; it is safe
        // because CreateLpVault is already gated to cfg.marketauth (the market's
        // top-level authority) and Live mode, above.
        let asset_index = domain as usize / 2;
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let mut profile = state::read_asset_oracle_profile(&market_data, asset_index)?;
            profile.backing_bucket_authority = registry_pda.to_bytes();
            state::write_asset_oracle_profile(&mut market_data, asset_index, &profile)?;
        }

        let market_bytes = market_ai.key.to_bytes();

        // Create the program-owned registry PDA account.
        let registry_len = state::lp_vault_registry_account_len();
        let registry_bump_bytes = [registry_bump];
        let registry_seeds: &[&[u8]] = &[
            crate::constants::LP_VAULT_REGISTRY_SEED,
            market_bytes.as_ref(),
            registry_bump_bytes.as_ref(),
        ];

        create_pda_account(
            admin,
            registry_ai,
            system_program_ai,
            registry_len,
            program_id,
            registry_seeds,
        )?;

        // Create the spl_token-owned LP share mint PDA account.
        let mint_len = spl_token::state::Mint::LEN;
        let mint_bump_bytes = [mint_bump];
        let mint_seeds: &[&[u8]] = &[
            crate::constants::LP_VAULT_MINT_SEED,
            market_bytes.as_ref(),
            mint_bump_bytes.as_ref(),
        ];

        create_pda_account(
            admin,
            mint_ai,
            system_program_ai,
            mint_len,
            token_program.key,
            mint_seeds,
        )?;

        // Initialize the LP share mint: authority = registry PDA, no freeze.
        let init_mint_ix = spl_token::instruction::initialize_mint2(
            token_program.key,
            mint_ai.key,
            &registry_pda,
            None,
            0,
        )?;
        invoke(&init_mint_ix, &[mint_ai.clone(), token_program.clone()])?;

        // Persist the registry config.
        let registry = state::LpVaultRegistryV16 {
            market_group: market_bytes,
            lp_mint: mint_ai.key.to_bytes(),
            total_lp_shares_outstanding: 0,
            insurance_fee_snapshot_atoms: 0,
            fee_distribution_total_atoms: 0,
            epoch: 0,
            redemption_cooldown_slots,
            fee_share_bps,
            oi_reservation_threshold_bps,
            domain,
            paused: 0,
            version: crate::constants::LP_VAULT_VERSION,
            bump: registry_bump,
            mint_bump,
            _padding: [0u8; 6],
            _reserved: [0u8; 16],
        };
        state::init_lp_vault_registry(&mut registry_ai.try_borrow_mut_data()?, &registry)?;
        Ok(())
    }

    /// LP Vault — DepositToLpVault (tag 75).
    ///
    /// Permissionless deposit: moves the depositor's collateral into the LP
    /// Vault's backing bucket and mints pro-rata LP shares.
    ///
    /// AUDIT MIRROR: the backing-bucket + BackingDomainLedger update sequence
    /// below is mirrored from handle_top_up_backing_bucket — change BOTH
    /// together.
    #[inline(never)]
    fn handle_deposit_to_lp_vault<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        amount: u128,
        target_domain: u16,
    ) -> ProgramResult {
        let depositor = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let mint_ai = account(accounts, 3)?;
        let depositor_lp_ata = account(accounts, 4)?;
        let source_token = account(accounts, 5)?;
        let vault_token = account(accounts, 6)?;
        let ledger_ai = account(accounts, 7)?;
        let token_program = account(accounts, 8)?;
        let system_program_ai = account(accounts, 9)?;
        // REQUIRED: the vault's OTHER domain ledger. NAV spans both pots, so
        // omitting it would understate NAV and mint the depositor free shares.
        // Pinned by address below; may be uninitialised (contributes 0).
        let sibling_ledger_ai = account(accounts, 10)?;

        expect_signer(depositor)?;
        expect_writable(depositor)?;
        expect_writable(market_ai)?;
        expect_writable(registry_ai)?;
        expect_writable(mint_ai)?;
        expect_writable(depositor_lp_ata)?;
        expect_writable(source_token)?;
        expect_writable(vault_token)?;
        expect_writable(ledger_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;
        verify_token_program(token_program)?;
        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if amount == 0 {
            return Err(PercolatorError::LpVaultZeroAmount.into());
        }

        // Registry shape + PDA binding.
        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        if registry.paused != 0 {
            return Err(PercolatorError::LpVaultPaused.into());
        }
        let (registry_pda, registry_bump) =
            state::derive_lp_vault_registry(program_id, market_ai.key);
        expect_key(registry_ai, &registry_pda)?;
        if registry.market_group != market_ai.key.to_bytes()
            || mint_ai.key.to_bytes() != registry.lp_mint
        {
            return Err(PercolatorError::LpVaultNotFound.into());
        }
        // Route to the requested pot. Both pots of the asset share one
        // `backing_bucket_authority`, so the vault is already authorised over
        // both; crossing to another asset is not permitted.
        if target_domain as usize / 2 != registry.domain as usize / 2 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let domain = target_domain as usize;
        // `ledger_ai` is always registry.domain's ledger and `sibling_ledger_ai`
        // always the other; both are pinned by address below, so picking between
        // them here cannot be steered by the caller.
        let target_is_sibling = target_domain != registry.domain;

        // Market preflight: Live + registry PDA is backing-bucket authority.
        let (cfg, mode, configured_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let asset_index = domain / 2;
        if domain >= configured_slots.saturating_mul(2) || asset_index >= configured_slots {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        {
            let market_data = market_ai.try_borrow_data()?;
            let profile = read_oracle_profile_for_asset(&market_data, &cfg, asset_index)?;
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
            if authorities.backing_bucket_authority != registry_pda.to_bytes() {
                return Err(PercolatorError::LpVaultAuthorityMismatch.into());
            }
        }

        // Token-account checks.
        let mint = primary_collateral_mint(&cfg);
        let (vault_authority, _) = derive_vault_authority(program_id, market_ai.key);
        verify_user_token_account(source_token, depositor.key, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;
        verify_user_token_account(depositor_lp_ata, depositor.key, mint_ai.key)?;
        let amount_u64 = amount_to_u64(amount)?;
        require_token_balance(source_token, amount_u64)?;

        // Backing-domain ledger PDA: lazily create on first deposit.
        let (ledger_pda, ledger_bump) =
            state::derive_lp_backing_ledger(program_id, market_ai.key, registry.domain);
        expect_key(ledger_ai, &ledger_pda)?;
        let (sibling_ledger_pda, sibling_ledger_bump) = state::derive_lp_backing_ledger(
            program_id,
            market_ai.key,
            sibling_domain(registry.domain),
        );
        expect_key(sibling_ledger_ai, &sibling_ledger_pda)?;
        // The routed pot's ledger is the one that gets written. Both candidates
        // are address-pinned above, so this selection is not caller-steerable.
        let (target_ledger_ai, target_ledger_bump) = if target_is_sibling {
            (sibling_ledger_ai, sibling_ledger_bump)
        } else {
            (ledger_ai, ledger_bump)
        };
        expect_writable(target_ledger_ai)?;
        if target_ledger_ai.data_is_empty() {
            let len = state::backing_domain_ledger_account_len();
            let target_domain_bytes = target_domain.to_le_bytes();
            let target_ledger_bump_bytes = [target_ledger_bump];
            let target_ledger_seeds: &[&[u8]] = &[
                crate::constants::LP_BACKING_LEDGER_SEED,
                market_ai.key.as_ref(),
                target_domain_bytes.as_ref(),
                target_ledger_bump_bytes.as_ref(),
            ];

            create_pda_account(
                depositor,
                target_ledger_ai,
                system_program_ai,
                len,
                program_id,
                target_ledger_seeds,
            )?;
        }

        let backing_num = amount
            .checked_mul(BOUND_SCALE)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;

        // ── Phase 1: NAV (pre-deposit) + shares computation, no mutation. ──
        let shares = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg_v, group) = state::market_view_mut(&mut market_data)?;
            let (_, bucket) = backing_domain_parts_view(&group, domain)?;
            let ledger_data = ledger_ai.try_borrow_data()?;
            let sibling_ledger_data = sibling_ledger_ai.try_borrow_data()?;
            let nav = lp_vault_combined_nav_atoms(
                &group,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                registry.domain,
                registry.fee_share_bps,
                &ledger_data,
                &sibling_ledger_data,
            )?;
            // #411: NAV above is derived ENTIRELY from the backing-domain ledgers, so it
            // does not see the vault's own accrued fee pool. Those fees belong to the LPs
            // who were carrying the vault while they were earned, but they only enter NAV
            // when someone calls the permissionless `LpVaultCrankFees` — which takes any
            // signer, is paid nothing, and can therefore run at an arbitrary time.
            //
            // Pricing without them let a deposit landing just before a crank buy into fees
            // it did not earn: the newcomer's shares were minted against the pre-harvest
            // NAV and revalued upward moments later at the existing LPs' expense. The same
            // vector was already fixed in percolator-stake.
            //
            // Adding the HARVESTABLE amount (not the raw claim — see the helper) makes the
            // quote independent of crank timing, which is the actual property that was
            // missing. No tokens move here; this only affects the share count.
            let harvestable = lp_vault_harvestable_fee_atoms(&cfg_v, &group)?;
            let nav = nav
                .checked_add(harvestable)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            percolator::lp_vault::lp_shares_for_deposit(
                amount,
                registry.total_lp_shares_outstanding,
                nav,
            )
            .map_err(map_v16_error)?
        };
        // Note 1: never silently mint 0 and absorb the deposit.
        if shares == 0 {
            return Err(PercolatorError::LpVaultZeroSharesMinted.into());
        }
        // BUG-2 / N7: dead-share floor on the vault's TRUE genesis deposit.
        // `shares` above is the FULL pro-rata amount (1:1 at genesis, since
        // `lp_shares_for_deposit` returns `amount` verbatim when
        // `registry.total_lp_shares_outstanding == 0`). That pre-deposit
        // outstanding count is the "is this genesis" signal. The floor is
        // carved out of the MINTED amount only: Phase 5 below still bumps
        // `registry.total_lp_shares_outstanding` by the FULL `shares`, so the
        // `LP_VAULT_MINIMUM_LIQUIDITY` difference is never minted to any
        // account and becomes permanently unredeemable dead supply — mirrors
        // percolator-stake's `apply_minimum_liquidity_lock`. Non-genesis
        // deposits are unaffected (mint the full computed amount, as before).
        let shares_to_mint = if registry.total_lp_shares_outstanding == 0 {
            shares
                .checked_sub(crate::constants::LP_VAULT_MINIMUM_LIQUIDITY)
                .filter(|&s| s != 0)
                .ok_or(PercolatorError::LpVaultDepositBelowMinimumLiquidity)?
        } else {
            shares
        };
        let shares_u64 = u64::try_from(shares_to_mint)
            .map_err(|_| PercolatorError::EngineArithmeticOverflow)?;

        // ── Phase 2: move depositor collateral into the backing vault. ──
        transfer_tokens(token_program, source_token, vault_token, depositor, amount_u64)?;

        // ── Phase 3: backing-bucket + ledger update. ──
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (cfg_v, mut group) = state::market_view_mut(&mut market_data)?;
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg_v, &group)?;
            let mut ledger_data = target_ledger_ai.try_borrow_mut_data()?;
            let (_, bucket) = backing_domain_parts_view(&group, domain)?;
            let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                &ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                target_domain,
                &bucket,
            )?;
            sync_backing_domain_ledger(&mut ledger, &bucket)?;
            let next_vault = group
                .header
                .vault
                .get()
                .checked_add(amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            add_fresh_counterparty_backing_view(
                &mut group,
                domain,
                backing_num,
                crate::constants::LP_VAULT_BACKING_EXPIRY_SLOT,
            )?;
            // #413: RE-BASELINE the impairment observation before booking the principal.
            //
            // `add_fresh_counterparty_backing_view` pays down the provider receivable
            // (`refill = min(amount_num, provider_receivable_num)`), which LOWERS
            // `bucket.consumed_liened_backing_num`. `sync_backing_domain_ledger` books any
            // drop in unavailable principal as `cumulative_recovery_atoms`, and it cannot
            // tell a genuine loss reversal from an LP putting new money in.
            //
            // Without this, the same atoms are counted twice — once here as principal, and
            // again on the NEXT sync as a recovery that reduces net impairment:
            //
            //     available = (P + R) − (L − R) = P − L + 2R
            //
            // Measured before the fix: a 300_000 refill overstated available principal by
            // exactly 300_000, and redemption pays out against that figure.
            //
            // The sync above ran against the PRE-refill bucket, so re-reading it here and
            // pinning the watermark is what makes the refill invisible to the next sync.
            // Only the baseline moves; no loss or recovery is booked either way.
            {
                let (_, bucket_after) = backing_domain_parts_view(&group, domain)?;
                ledger.last_observed_unavailable_principal_atoms =
                    backing_unavailable_principal_atoms(&bucket_after)?;
            }
            ledger.total_principal_atoms = ledger
                .total_principal_atoms
                .checked_add(amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            ledger.total_deposited_atoms = ledger
                .total_deposited_atoms
                .checked_add(amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            group.header.vault = percolator::V16PodU128::new(next_vault);
            group.validate_shape().map_err(map_v16_error)?;
            write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)?;
        }

        // ── Phase 4: mint LP shares to depositor (registry PDA signs). ──
        let mint_ix = spl_token::instruction::mint_to(
            token_program.key,
            mint_ai.key,
            depositor_lp_ata.key,
            &registry_pda,
            &[],
            shares_u64,
        )?;
        invoke_signed(
            &mint_ix,
            &[
                mint_ai.clone(),
                depositor_lp_ata.clone(),
                registry_ai.clone(),
                token_program.clone(),
            ],
            &[&[
                crate::constants::LP_VAULT_REGISTRY_SEED,
                market_ai.key.as_ref(),
                &[registry_bump],
            ]],
        )?;

        // ── Phase 5: bump outstanding shares. ──
        {
            let mut reg = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
            reg.total_lp_shares_outstanding = reg
                .total_lp_shares_outstanding
                .checked_add(shares)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            state::write_lp_vault_registry(&mut registry_ai.try_borrow_mut_data()?, &reg)?;
        }
        Ok(())
    }

    /// LP Vault — RequestRedeemLpShares (tag 76).
    ///
    /// Step 1 of the two-step redemption. Escrows the redeemer's LP shares
    /// and records a redemption request. `total_lp_shares_outstanding` is
    /// UNCHANGED here — shares are escrowed, not burned (I2 invariant).
    #[inline(never)]
    fn handle_request_redeem_lp_shares<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        shares: u128,
    ) -> ProgramResult {
        let redeemer = account(accounts, 0)?;
        let registry_ai = account(accounts, 1)?;
        let lp_mint = account(accounts, 2)?;
        let redeemer_lp_ata = account(accounts, 3)?;
        let escrow_ai = account(accounts, 4)?;
        let redemption_ai = account(accounts, 5)?;
        let token_program = account(accounts, 6)?;
        let system_program_ai = account(accounts, 7)?;

        expect_signer(redeemer)?;
        expect_writable(redeemer)?;
        expect_writable(redeemer_lp_ata)?;
        expect_writable(escrow_ai)?;
        expect_writable(redemption_ai)?;
        expect_owner(registry_ai, program_id)?;
        verify_token_program(token_program)?;
        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if shares == 0 {
            return Err(PercolatorError::LpVaultZeroAmount.into());
        }

        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        if registry.paused != 0 {
            return Err(PercolatorError::LpVaultPaused.into());
        }
        let market_key = Pubkey::new_from_array(registry.market_group);
        let (registry_pda, _) = state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        if lp_mint.key.to_bytes() != registry.lp_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        verify_user_token_account(redeemer_lp_ata, redeemer.key, lp_mint.key)?;
        let shares_u64 =
            u64::try_from(shares).map_err(|_| PercolatorError::EngineArithmeticOverflow)?;
        require_token_balance(redeemer_lp_ata, shares_u64)?;

        // Escrow ATA (registry-owned, shared per vault): lazily created.
        let (escrow_pda, escrow_bump) = state::derive_lp_escrow(program_id, &market_key);
        expect_key(escrow_ai, &escrow_pda)?;
        if escrow_ai.data_is_empty() {
            let len = spl_token::state::Account::LEN;
            let escrow_bump_bytes = [escrow_bump];
            let escrow_seeds: &[&[u8]] = &[
                crate::constants::LP_ESCROW_SEED,
                market_key.as_ref(),
                escrow_bump_bytes.as_ref(),
            ];

            create_pda_account(
                redeemer,
                escrow_ai,
                system_program_ai,
                len,
                token_program.key,
                escrow_seeds,
            )?;

            let init_ix = spl_token::instruction::initialize_account3(
                token_program.key,
                escrow_ai.key,
                lp_mint.key,
                &registry_pda,
            )?;
            invoke(&init_ix, &[escrow_ai.clone(), lp_mint.clone(), token_program.clone()])?;
        }

        // Redemption PDA: one pending request per (registry, redeemer). Fail
        // closed if a request already exists (must execute/cancel first).
        let (redemption_pda, redemption_bump) =
            state::derive_lp_redemption(program_id, &registry_pda, redeemer.key);
        expect_key(redemption_ai, &redemption_pda)?;
        if !redemption_ai.data_is_empty() {
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        {
            let rlen = state::lp_redemption_account_len();
            let redemption_bump_bytes = [redemption_bump];
            let redemption_seeds: &[&[u8]] = &[
                crate::constants::LP_REDEMPTION_SEED,
                registry_pda.as_ref(),
                redeemer.key.as_ref(),
                redemption_bump_bytes.as_ref(),
            ];

            create_pda_account(
                redeemer,
                redemption_ai,
                system_program_ai,
                rlen,
                program_id,
                redemption_seeds,
            )?;
        }

        // Escrow the shares (redeemer signs — owns the source).
        transfer_tokens(token_program, redeemer_lp_ata, escrow_ai, redeemer, shares_u64)?;

        // Record the request. total_lp_shares_outstanding UNCHANGED (I2 holds).
        let now_slot = Clock::get().map(|c| c.slot).unwrap_or(0);
        let redemption = state::LpRedemptionV16 {
            registry: registry_pda.to_bytes(),
            redeemer: redeemer.key.to_bytes(),
            shares,
            request_slot: now_slot,
            version: crate::constants::LP_VAULT_VERSION,
            bump: redemption_bump,
            _padding: [0u8; 6],
        };
        state::init_lp_redemption(&mut redemption_ai.try_borrow_mut_data()?, &redemption)?;
        Ok(())
    }

    /// LP Vault — ExecuteRedemption (tag 77).
    ///
    /// Step 2: after cooldown, pays the redeemer their pro-rata share and burns
    /// the escrowed shares. Permissionless.
    ///
    /// DOUBLE-EXECUTE REPLAY GUARD: first reads the redemption PDA (fails
    /// NotInitialized if magic was zeroed by a prior consume), last zeros it.
    ///
    /// AUDIT MIRROR: the backing decrement sequence mirrors handle_withdraw_backing_bucket.
    /// The RESYNC 5ebd136 dual-withdraw gate is preserved: source watermark is
    /// checked post-decrement; EngineLockActive if credit_rate_num < CREDIT_RATE_SCALE.
    #[inline(never)]
    /// LP Vault — RebalanceLpVaultBacking (tag 91).
    ///
    /// Moves IDLE (fresh, unliened) backing between the two domains of the
    /// vault's asset, carrying ledger principal in lockstep so NAV stays in
    /// sync with the buckets. No tokens move: `header.vault` is untouched and
    /// the `source_fresh_backing_total_num` aggregate nets to zero (the source
    /// decrement below cancels the increment inside
    /// `add_fresh_counterparty_backing_view`).
    ///
    /// WHY THIS EXISTS: `CreateLpVault` welds the vault to ONE domain, but the
    /// house takes whichever side traders leave it and draws its gains from the
    /// OPPOSITE domain. spec.md L410 requires refill be "source-domain local",
    /// so a vault that cannot reach both domains of its asset leaves one side
    /// permanently unfundable. `backing_bucket_authority` is stored PER ASSET,
    /// so the registry PDA is already authorised for both domains.
    ///
    /// Permissionless: moving idle backing between two pots owned by the same
    /// vault cannot extract value, and the source-side gate below refuses any
    /// move that would leave the source domain under-backed.
    #[inline(never)]
    fn handle_rebalance_lp_vault_backing<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        from_domain: u16,
        to_domain: u16,
        amount: u128,
    ) -> ProgramResult {
        let cranker = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let from_ledger_ai = account(accounts, 3)?;
        let to_ledger_ai = account(accounts, 4)?;
        let system_program_ai = account(accounts, 5)?;

        expect_signer(cranker)?;
        expect_writable(cranker)?;
        expect_writable(market_ai)?;
        expect_writable(from_ledger_ai)?;
        expect_writable(to_ledger_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;
        expect_owner(from_ledger_ai, program_id)?;
        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if amount == 0 {
            return Err(PercolatorError::LpVaultZeroAmount.into());
        }
        if from_domain == to_domain {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        if registry.paused != 0 {
            return Err(PercolatorError::LpVaultPaused.into());
        }
        let market_key = Pubkey::new_from_array(registry.market_group);
        expect_key(market_ai, &market_key)?;
        let (registry_pda, _) = state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;

        // Both domains must belong to the SAME asset as the vault. The per-asset
        // `backing_bucket_authority` only authorises this vault over its own
        // asset; crossing assets would move another asset's backing.
        let asset_index = registry.domain as usize / 2;
        if from_domain as usize / 2 != asset_index || to_domain as usize / 2 != asset_index {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        // Pin BOTH ledger addresses. This program owns every (market, domain)
        // ledger, so an owner check alone would admit any other domain's ledger.
        let (from_ledger_pda, _) =
            state::derive_lp_backing_ledger(program_id, &market_key, from_domain);
        expect_key(from_ledger_ai, &from_ledger_pda)?;
        let (to_ledger_pda, to_ledger_bump) =
            state::derive_lp_backing_ledger(program_id, &market_key, to_domain);
        expect_key(to_ledger_ai, &to_ledger_pda)?;

        let (cfg, mode, configured_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        // Live OR Resolved — deliberately the SAME gate ExecuteRedemption uses
        // (`:15583`), because this instruction exists to make redemption feasible.
        //
        // #419: redemption prices an LP's payout across the COMBINED pots
        // (`lp_vault_combined_available_principal_atoms`) but draws it from ONE
        // (`principal_portion > ledger.total_principal_atoms` -> EngineCounterUnderflow).
        // Once an LP's proportional claim exceeds either single pot, BOTH choices of
        // `source_domain` fail, and consolidating the pots is the only remedy. With
        // this gate at `Live` only, resolving such a market stranded the LP's capital
        // permanently: no domain could pay, and the one instruction that would fix it
        // was refused. Reproduced end-to-end: both draws Custom(25), rebalance
        // Custom(21), LP paid 0.
        //
        // Safe in Resolved for the same reasons it is permissionless in Live, none of
        // which reference the mode: NO TOKENS MOVE (`header.vault` is untouched and the
        // `source_fresh_backing_total_num` aggregate nets to zero), both pots belong to
        // the SAME vault so no value can be extracted, only FRESH UNLIENED backing is
        // movable, and the source-side watermark gate below still refuses any move that
        // would leave the source domain under-backed. Resolved is if anything the safer
        // mode, since there is no live OI for the moved backing to be supporting.
        //
        // Terminal modes other than Resolved stay barred.
        if mode != MarketModeV16::Live && mode != MarketModeV16::Resolved {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if from_domain as usize >= configured_slots.saturating_mul(2)
            || to_domain as usize >= configured_slots.saturating_mul(2)
            || asset_index >= configured_slots
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        {
            let market_data = market_ai.try_borrow_data()?;
            let profile = read_oracle_profile_for_asset(&market_data, &cfg, asset_index)?;
            let authorities = domain_authorities_from_profile(&cfg, &profile, asset_index);
            if authorities.backing_bucket_authority != registry_pda.to_bytes() {
                return Err(PercolatorError::LpVaultAuthorityMismatch.into());
            }
        }

        // Destination ledger is lazily created on first arrival, exactly as
        // handle_deposit_to_lp_vault does for its own domain.
        if to_ledger_ai.data_is_empty() {
            let len = state::backing_domain_ledger_account_len();
            let to_domain_bytes = to_domain.to_le_bytes();
            let to_ledger_bump_bytes = [to_ledger_bump];
            let to_ledger_seeds: &[&[u8]] = &[
                crate::constants::LP_BACKING_LEDGER_SEED,
                market_ai.key.as_ref(),
                to_domain_bytes.as_ref(),
                to_ledger_bump_bytes.as_ref(),
            ];

            create_pda_account(
                cranker,
                to_ledger_ai,
                system_program_ai,
                len,
                program_id,
                to_ledger_seeds,
            )?;
        }

        let backing_num = amount
            .checked_mul(BOUND_SCALE)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;

        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg_v, mut group) = state::market_view_mut(&mut market_data)?;
        // The ENGINE-side twin of the mode gate above, and it must agree with it.
        // 0 = Live, 1 = Resolved (`MarketModeV16::Resolved => 1`). #419: this one
        // carried no comment and was the gate that actually kept firing after the
        // header gate was relaxed — the LP still saw Custom(21). Both have to move
        // together or the fix is invisible.
        if group.header.mode != 0 && group.header.mode != 1 {
            return Err(PercolatorError::EngineLockActive.into());
        }
        // Live-only by construction: it rejects a LIVE market that has already matured
        // past its permissionless-resolve deadline. A Resolved market is the state that
        // check exists to force, so applying it there would bar the very mode it wants.
        if group.header.mode == 0 {
            reject_permissionless_resolve_matured_live_view(&cfg_v, &group)?;
        }

        // ── Source side: withdraw idle backing. Mirrors the withdrawability gate
        //    in percolator::v16::prepare_counterparty_backing_withdraw_delta plus
        //    the RESYNC 5ebd136 dual watermark gate from handle_execute_redemption,
        //    so a rebalance can never leave the source domain under-backed.
        {
            let mut from_ledger_data = from_ledger_ai.try_borrow_mut_data()?;
            let (from_source, from_bucket) =
                backing_domain_parts_view(&group, from_domain as usize)?;
            let (mut from_ledger, from_initialized) = read_or_new_backing_domain_ledger(
                &from_ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                from_domain,
                &from_bucket,
            )?;
            sync_backing_domain_ledger(&mut from_ledger, &from_bucket)?;
            if from_bucket.status != BackingBucketStatusV16::Fresh
                || from_bucket.fresh_unliened_backing_num < backing_num
                || from_source.fresh_reserved_backing_num < backing_num
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            // Only PRINCIPAL moves; earnings stay with the domain that earned them.
            if amount > from_ledger.total_principal_atoms {
                return Err(PercolatorError::EngineCounterUnderflow.into());
            }

            let mut bucket = from_bucket;
            let mut source = from_source;
            bucket.fresh_unliened_backing_num -= backing_num;
            source.fresh_reserved_backing_num -= backing_num;
            if bucket.fresh_unliened_backing_num == 0 && bucket.valid_liened_backing_num == 0 {
                if bucket.impaired_liened_backing_num != 0 {
                    bucket.status = BackingBucketStatusV16::Impaired;
                } else if bucket.consumed_liened_backing_num != 0 {
                    bucket.status = BackingBucketStatusV16::Expired;
                } else {
                    bucket.status = BackingBucketStatusV16::Empty;
                    bucket.expiry_slot = 0;
                }
            }
            source.credit_rate_num =
                expected_source_credit_rate_num(source).map_err(map_v16_error)?;
            if source.credit_rate_num != percolator::CREDIT_RATE_SCALE {
                return Err(PercolatorError::EngineLockActive.into());
            }
            source.credit_epoch = source
                .credit_epoch
                .checked_add(1)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            {
                let slot = &mut group.markets[asset_index].engine;
                let (source_acc, bucket_acc) = if from_domain % 2 == 0 {
                    (&mut slot.source_credit_long, &mut slot.backing_long)
                } else {
                    (&mut slot.source_credit_short, &mut slot.backing_short)
                };
                *source_acc = percolator::SourceCreditStateV16Account::from_runtime(&source);
                *bucket_acc = percolator::BackingBucketV16Account::from_runtime(&bucket);
            }
            // Cancels the increment inside add_fresh_counterparty_backing_view below.
            group.header.source_fresh_backing_total_num = percolator::V16PodU128::new(
                group
                    .header
                    .source_fresh_backing_total_num
                    .get()
                    .checked_sub(backing_num)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?,
            );
            from_ledger.total_principal_atoms -= amount;
            write_or_init_backing_domain_ledger(
                &mut from_ledger_data,
                &from_ledger,
                from_initialized,
            )?;
        }

        // ── Destination side: deposit the same backing. ──
        {
            let mut to_ledger_data = to_ledger_ai.try_borrow_mut_data()?;
            // #413: sync against the PRE-refill bucket, exactly as the deposit path does.
            //
            // `add_fresh_counterparty_backing_view` pays down the provider receivable and
            // so LOWERS `consumed_liened_backing_num`. Syncing AFTER it — which is what
            // this block used to do — makes `sync_backing_domain_ledger` read that drop as
            // `cumulative_recovery_atoms`, while the principal is added just below. The
            // same atoms then count twice and available principal is overstated by the
            // moved amount.
            //
            // Order matters and is the whole fix: sync first (so genuine losses and
            // earnings since the last observation are still booked), refill, then pin the
            // watermark to the post-refill value so the NEXT sync sees no phantom recovery.
            // Suppressing the sync outright would have been simpler and wrong — it would
            // also swallow real impairment that happened before this instruction.
            let (_, to_bucket_pre) = backing_domain_parts_view(&group, to_domain as usize)?;
            let (mut to_ledger, to_initialized) = read_or_new_backing_domain_ledger(
                &to_ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                to_domain,
                &to_bucket_pre,
            )?;
            sync_backing_domain_ledger(&mut to_ledger, &to_bucket_pre)?;
            add_fresh_counterparty_backing_view(
                &mut group,
                to_domain as usize,
                backing_num,
                crate::constants::LP_VAULT_BACKING_EXPIRY_SLOT,
            )?;
            {
                let (_, to_bucket_post) = backing_domain_parts_view(&group, to_domain as usize)?;
                to_ledger.last_observed_unavailable_principal_atoms =
                    backing_unavailable_principal_atoms(&to_bucket_post)?;
            }
            to_ledger.total_principal_atoms = to_ledger
                .total_principal_atoms
                .checked_add(amount)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            write_or_init_backing_domain_ledger(&mut to_ledger_data, &to_ledger, to_initialized)?;
        }

        group.header.risk_epoch = percolator::V16PodU64::new(
            group
                .header
                .risk_epoch
                .get()
                .checked_add(1)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?,
        );
        group.validate_shape().map_err(map_v16_error)?;
        Ok(())
    }

    fn handle_execute_redemption<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        source_domain: u16,
    ) -> ProgramResult {
        let cranker = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let redemption_ai = account(accounts, 3)?;
        let lp_mint = account(accounts, 4)?;
        let escrow_ai = account(accounts, 5)?;
        let vault_token = account(accounts, 6)?;
        let vault_authority_ai = account(accounts, 7)?;
        let ledger_ai = account(accounts, 8)?;
        let redeemer_dest = account(accounts, 9)?;
        let token_program = account(accounts, 10)?;
        // REQUIRED: the vault's OTHER domain ledger. NAV and available-principal
        // both span the two pots; omitting it would underpay the redeemer by
        // whatever sits in the sibling. Pinned by address below.
        let sibling_ledger_ai = account(accounts, 11)?;

        expect_signer(cranker)?;
        expect_writable(market_ai)?;
        expect_writable(registry_ai)?;
        expect_writable(redemption_ai)?;
        expect_writable(lp_mint)?;
        expect_writable(escrow_ai)?;
        expect_writable(vault_token)?;
        expect_writable(redeemer_dest)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;
        expect_owner(redemption_ai, program_id)?;
        verify_token_program(token_program)?;

        // ── REPLAY GUARD: rejects NotInitialized if magic was zeroed. ──
        let redemption = state::read_lp_redemption(&redemption_ai.try_borrow_data()?)?;
        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;

        // Bindings.
        let market_key = Pubkey::new_from_array(registry.market_group);
        expect_key(market_ai, &market_key)?;
        let (registry_pda, registry_bump) =
            state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        if redemption.registry != registry_pda.to_bytes() {
            return Err(PercolatorError::LpVaultNotFound.into());
        }
        let redeemer = Pubkey::new_from_array(redemption.redeemer);
        let (redemption_pda, _) =
            state::derive_lp_redemption(program_id, &registry_pda, &redeemer);
        expect_key(redemption_ai, &redemption_pda)?;
        if lp_mint.key.to_bytes() != registry.lp_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        let (escrow_pda, _) = state::derive_lp_escrow(program_id, &market_key);
        expect_key(escrow_ai, &escrow_pda)?;
        // Backing-domain ledger: pin the ADDRESS, not just the owner. Every
        // other site that touches this ledger does — `handle_deposit_to_lp_vault`
        // and `handle_lp_vault_crank_fees` both `expect_key` against this same
        // derivation. Owner-only is not enough: this program owns every backing
        // ledger for every (market, domain) pair, so an owner check alone admits
        // ANY other market's or domain's ledger. This handler reads
        // `total_principal_atoms` / `cumulative_loss_atoms` from it to price the
        // redemption and then writes the decremented principal back, so a
        // substituted ledger both misprices the payout and corrupts the ledger
        // it was swapped in from.
        let (ledger_pda, _) =
            state::derive_lp_backing_ledger(program_id, &market_key, registry.domain);
        expect_key(ledger_ai, &ledger_pda)?;
        let (sibling_ledger_pda, _) = state::derive_lp_backing_ledger(
            program_id,
            &market_key,
            sibling_domain(registry.domain),
        );
        expect_key(sibling_ledger_ai, &sibling_ledger_pda)?;
        // Pick the pot the payout is physically drawn from. NAV and
        // available-principal remain COMBINED, so this cannot change the amount
        // owed — only its source. With routed deposits the vault's own-domain
        // ledger may not even exist, so the blanket owner check that used to sit
        // above moved here, onto the pot actually being touched.
        if source_domain as usize / 2 != registry.domain as usize / 2 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        // Deliberately NOT shadowing `ledger_ai`: combined NAV must keep reading
        // OWN + SIBLING. Shadowing would make it read the sibling twice and drop
        // the own pot entirely, mispricing every redemption.
        let source_ledger_ai = if source_domain == registry.domain {
            ledger_ai
        } else {
            sibling_ledger_ai
        };
        expect_writable(source_ledger_ai)?;
        expect_owner(source_ledger_ai, program_id)?;

        // ── Cooldown gate. ──
        let now_slot = Clock::get().map(|c| c.slot).unwrap_or(0);
        if !percolator::lp_vault::lp_redemption_cooldown_elapsed(
            redemption.request_slot,
            now_slot,
            registry.redemption_cooldown_slots,
        ) {
            return Err(PercolatorError::LpVaultCooldownActive.into());
        }

        let domain = source_domain as usize;
        let asset_index = domain / 2;

        // Collateral mint + vault authority + redeemer dest checks.
        let (cfg, mode, configured_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if mode != MarketModeV16::Live && mode != MarketModeV16::Resolved {
            return Err(PercolatorError::EngineLockActive.into());
        }
        if domain >= configured_slots.saturating_mul(2) || asset_index >= configured_slots {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let mint = primary_collateral_mint(&cfg);
        let (vault_authority, vault_bump) = derive_vault_authority(program_id, market_ai.key);
        expect_key(vault_authority_ai, &vault_authority)?;
        verify_user_token_account(redeemer_dest, &redeemer, &mint)?;
        verify_vault_token_account(vault_token, &vault_authority, &mint)?;

        // ── NAV (pre-withdraw) → atoms (round DOWN). ──
        //
        // SPLIT: atoms = principal_portion + earnings_portion.
        //   principal_portion = floor(shares * available_principal / total_shares)
        //   earnings_portion  = atoms - principal_portion
        //
        // Only principal_portion is routed through the fresh-unliened backing
        // path (bucket.fresh_unliened_backing_num decrement). earnings_portion
        // is routed through withdraw_backing_provider_earnings_not_atomic and
        // booked to total_earnings_withdrawn_atoms (GROSS convention, mirroring
        // `handle_withdraw_backing_bucket_earnings`, which books the same way).
        // The insurance-side stub ((1-fee_share) of gross net_earnings) stays
        // in the bucket — it was never counted in LP NAV and no token moves for
        // it. This is the only correct split; see lp_vault_design.md §5.2 Note 3.
        let (atoms, principal_portion, earnings_portion) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (_, group) = state::market_view_mut(&mut market_data)?;
            let (_, bucket) = backing_domain_parts_view(&group, domain)?;
            let ledger_data = ledger_ai.try_borrow_data()?;
            let (mut ledger, _) = read_or_new_backing_domain_ledger(
                &ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                registry.domain,
                &bucket,
            )?;
            sync_backing_domain_ledger(&mut ledger, &bucket)?;
            // NAV and available_principal BOTH span the vault's two pots — see
            // lp_vault_combined_available_principal_atoms for why they must agree.
            let sibling_ledger_data = sibling_ledger_ai.try_borrow_data()?;
            let available_principal = lp_vault_combined_available_principal_atoms(
                &group,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                registry.domain,
                &ledger_data,
                &sibling_ledger_data,
            )?;
            let nav = lp_vault_combined_nav_atoms(
                &group,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                registry.domain,
                registry.fee_share_bps,
                &ledger_data,
                &sibling_ledger_data,
            )?;
            let atoms_out = percolator::lp_vault::lp_atoms_for_redemption(
                redemption.shares,
                registry.total_lp_shares_outstanding,
                nav,
            )
            .map_err(map_v16_error)?;
            // principal_portion = floor(shares * available_principal / total_shares).
            // Rounds down — consistent with lp_atoms_for_redemption. Never exceeds atoms_out
            // because available_principal <= nav.
            let principal_out = percolator::wide_math::wide_mul_div_floor_u128(
                redemption.shares,
                available_principal,
                registry.total_lp_shares_outstanding,
            );
            let earnings_out = atoms_out
                .checked_sub(principal_out)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            (atoms_out, principal_out, earnings_out)
        };
        // Dust-share redemption rounding to 0 atoms would burn shares for no
        // payout — reject.
        if atoms == 0 {
            return Err(PercolatorError::LpVaultZeroAmount.into());
        }
        let atoms_u64 = amount_to_u64(atoms)?;
        // backing_num is derived from principal_portion only (the fresh-unliened
        // backing path handles principal, not earnings).
        let backing_num = principal_portion
            .checked_mul(BOUND_SCALE)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;

        // ECONOMICALLY-CORRECT gross earnings consumed by this redemption.
        //
        // Problem with the 89382f1 model (increments total_earnings_withdrawn_atoms
        // by earnings_portion, the LP's fee_share slice): remaining lp_earnings for
        // future LPs = floor((net - earnings_portion) * fee_share / 10_000) which
        // does NOT drop by exactly earnings_portion. Over redemption cycles, future
        // LPs can extract part of the insurance stub beyond their fee_share.
        //
        // Correct model: consumption of gross_consumed atoms from the earnings pool
        // reduces lp_earnings by exactly earnings_portion:
        //   floor((net - gross_consumed) * fee_share / 10_000)
        //     = floor(net * fee_share / 10_000) - earnings_portion
        //
        // The gross chunk that maps to earnings_portion LP atoms via the fee_share split:
        //   gross_consumed = ceil(earnings_portion * 10_000 / fee_share_bps)
        //
        // When fee_share_bps > 0: the ceiling ensures we don't under-subtract
        // (remaining lp_earnings ≤ floor lp_earnings before, erring conservative).
        // When earnings_portion == 0 (fee_share == 0 OR no earnings): gross_consumed = 0.
        //
        // What happens to the insurance stub atoms (gross_consumed - earnings_portion)?
        // They stay in the vault — they were never paid out. We remove them from
        // bucket.utilization_fee_earnings (that gross chunk is consumed), but the
        // vault only decrements by earnings_portion (the LP payout). The difference
        // remains in the vault as un-withdrawn insurance reserve.
        let gross_consumed: u128 = if earnings_portion == 0 {
            0
        } else {
            // fee_share_bps > 0 is guaranteed when earnings_portion > 0:
            // lp_earnings = floor(net * fee_share / 10_000). If fee_share == 0
            // then lp_earnings == 0, atoms == available_principal, earnings_portion == 0.
            // So the branch above catches fee_share == 0 safely.
            let result = percolator::wide_math::mul_div_ceil_u256(
                percolator::wide_math::U256::from_u128(earnings_portion),
                percolator::wide_math::U256::from_u128(percolator::MAX_MARGIN_BPS as u128),
                percolator::wide_math::U256::from_u128(registry.fee_share_bps as u128),
            );
            result
                .try_into_u128()
                .ok_or(PercolatorError::EngineArithmeticOverflow)?
        };

        // ── Inline withdraw — MIRRORS handle_withdraw_backing_bucket. ──
        {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            // `group` is mut: the LPVAULT-359 stub credit (#381) calls the &mut self engine
            // method credit_domain_insurance_budget_not_atomic, and the bucket writes below
            // borrow group.markets[..] mutably.
            let (cfg_v, mut group) = state::market_view_mut(&mut market_data)?;
            // #377: allow LP redemption in the terminal-flat Resolved state, not just Live.
            // mode 0 = Live; mode 1 = Resolved, permitted only when terminal-flat (no
            // materialized portfolios AND zero trader collateral → the LP withdraws only its
            // own backing); mode 2 = Recovery and any non-terminal Resolved stay blocked.
            match group.header.mode {
                0 => {}
                1 if group.header.materialized_portfolio_count.get() == 0
                    && group.header.c_tot.get() == 0 => {}
                _ => return Err(PercolatorError::EngineLockActive.into()),
            }
            // Registry must be the backing authority for this domain.
            let authorities = domain_authorities_from_view(&group, &cfg_v, domain)?;
            if authorities.backing_bucket_authority != registry_pda.to_bytes() {
                return Err(PercolatorError::LpVaultAuthorityMismatch.into());
            }
            if asset_index >= group.markets.len()
                || asset_index >= group.header.config.max_market_slots.get() as usize
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            let (source_acc, bucket_acc) = if domain % 2 == 0 {
                (
                    &mut group.markets[asset_index].engine.source_credit_long,
                    &mut group.markets[asset_index].engine.backing_long,
                )
            } else {
                (
                    &mut group.markets[asset_index].engine.source_credit_short,
                    &mut group.markets[asset_index].engine.backing_short,
                )
            };
            let mut source = source_acc.try_to_runtime().map_err(map_v16_error)?;
            let mut bucket = bucket_acc.try_to_runtime().map_err(map_v16_error)?;
            let mut ledger_data = source_ledger_ai.try_borrow_mut_data()?;
            let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                &ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                source_domain,
                &bucket,
            )?;
            sync_backing_domain_ledger(&mut ledger, &bucket)?;
            // Liveness guard: principal_portion must not exceed available principal.
            // (Pre-split bug: this compared `atoms` which includes earnings — could
            // incorrectly block redemptions once earnings make NAV > total_principal.)
            if principal_portion > ledger.total_principal_atoms {
                return Err(PercolatorError::EngineCounterUnderflow.into());
            }
            // Same withdrawability gate as handle_withdraw_backing_bucket
            // (percolator::v16::withdraw_fresh_counterparty_backing_not_atomic /
            // prepare_counterparty_backing_withdraw_delta, v16.rs): Fresh
            // status + availability only. A live source-credit lien
            // (positive_claim_bound_num != 0) does NOT itself block a
            // redemption -- it is the PROPORTIONAL stay-fully-backed check
            // below (the "RESYNC 5ebd136 DUAL withdraw-gate" block, which
            // recomputes credit_rate_num on the POST-decrement source and
            // requires it stay == CREDIT_RATE_SCALE) that enforces solvency,
            // exactly mirroring the admin withdraw path. Only a withdrawal
            // that would leave the domain under-backed relative to its
            // outstanding claim is rejected; a withdrawal against a
            // fully-covered lien is not. backing_num is derived from
            // principal_portion; vault check uses full atoms.
            if bucket.status != BackingBucketStatusV16::Fresh
                || bucket.fresh_unliened_backing_num < backing_num
                || source.fresh_reserved_backing_num < backing_num
                || atoms > group.header.vault.get()
            {
                return Err(PercolatorError::EngineLockActive.into());
            }
            // Earnings availability gate: earnings pool must cover the LP's earnings slice.
            if earnings_portion > bucket.utilization_fee_earnings {
                return Err(PercolatorError::EngineLockActive.into());
            }
            // OI reservation guard: leave nav_post * threshold/10_000 of
            // outstanding backing covered. nav_post is computed from the full
            // post-redeem NAV (available_principal_post + lp_earnings_post).
            //
            // LP-VAULT-REDEEM-BUG fix (2026-07-17): outstanding_post is the
            // backing actually AT RISK against real open interest, i.e. the
            // bucket's `valid_liened_backing_num` only. The prior formula
            // additionally folded in `fresh_unliened_backing_num` (idle,
            // uncommitted LP capital with no OI against it) after subtracting
            // this redemption's principal, so it was really measuring "all
            // capital left in the vault," not "capital at risk." Since no
            // wrapper instruction in this build ever writes
            // `valid_liened_backing_num` on a real trade (it is always 0 on
            // every deployed vault today), the old formula degenerated into an
            // unconditional NAV-surplus-over-idle-capital requirement that
            // rejected every ordinary, fully-solvent, zero-OI redemption for
            // any nonzero oi_reservation_threshold_bps -- while providing zero
            // actual OI protection, since there was never real OI to protect.
            // This one-line fix restores the guard's intended meaning: reject
            // only when the redemption would leave *real* liened OI
            // insufficiently covered by post-redeem NAV. See
            // execute_redemption_oi_reservation_clean_bucket_partial_succeeds /
            // execute_redemption_oi_reservation_clean_bucket_full_succeeds
            // (accept path) and execute_redemption_oi_reservation_violation_rejects
            // (genuine-lien reject path, solvency-preserving) in
            // tests/v16_fork_lp_vault_redeem.rs.
            if registry.oi_reservation_threshold_bps != 0 {
                let outstanding_post = bucket.valid_liened_backing_num;
                // Post-redeem NAV: recompute with post-withdrawal counters.
                let post_principal = ledger
                    .total_principal_atoms
                    .checked_sub(principal_portion)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                // Use gross_consumed (not earnings_portion) so nav_post reflects
                // the correct remaining net_earnings for the fee_share split.
                let post_earnings_withdrawn = ledger
                    .total_earnings_withdrawn_atoms
                    .checked_add(gross_consumed)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                let nav_post_atoms = percolator::lp_vault::lp_vault_nav_atoms(
                    post_principal,
                    ledger.total_earnings_atoms,
                    post_earnings_withdrawn,
                    ledger.cumulative_loss_atoms,
                    ledger.cumulative_recovery_atoms,
                    registry.fee_share_bps,
                )
                .map_err(map_v16_error)?;
                let nav_post_num = nav_post_atoms
                    .checked_mul(BOUND_SCALE)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                let covered = nav_post_num
                    .checked_mul(registry.oi_reservation_threshold_bps as u128)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?
                    / 10_000u128;
                if covered < outstanding_post {
                    return Err(PercolatorError::LpVaultOiReservationViolated.into());
                }
            }
            // ── Principal-side bucket mutation. ──
            bucket.fresh_unliened_backing_num = bucket
                .fresh_unliened_backing_num
                .checked_sub(backing_num)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            if bucket.fresh_unliened_backing_num == 0 && bucket.valid_liened_backing_num == 0 {
                if bucket.impaired_liened_backing_num != 0 {
                    bucket.status = BackingBucketStatusV16::Impaired;
                } else if bucket.consumed_liened_backing_num != 0 {
                    bucket.status = BackingBucketStatusV16::Expired;
                } else {
                    bucket.status = BackingBucketStatusV16::Empty;
                    bucket.expiry_slot = 0;
                }
            }
            // ── Earnings-side bucket mutation (inline — bypasses vault decrement
            //    in withdraw_backing_provider_earnings_not_atomic since vault is
            //    decremented once below by earnings_portion only).
            //
            // ECONOMICALLY-CORRECT earnings accounting (v17 supersedes 89382f1):
            //
            // We consume gross_consumed atoms from bucket.utilization_fee_earnings
            // (the gross earnings pool). Of these, earnings_portion is paid to the LP
            // (physically leaves the vault). The remaining insurance stub
            // (gross_consumed - earnings_portion) stays IN the vault — the vault only
            // decrements by earnings_portion below, keeping the insurance portion safe.
            //
            // This ensures remaining LPs' lp_earnings drops by exactly earnings_portion:
            //   lp_earnings_after = floor((net - gross_consumed) * fee_share / 10_000)
            //                     = lp_earnings_before - earnings_portion
            //
            // 89382f1 error: consumed only earnings_portion (LP slice) from gross pool,
            // so remaining net_earnings was overstated and future LPs could extract the
            // insurance stub via their NAV computation.
            if gross_consumed > 0 {
                bucket.utilization_fee_earnings = bucket
                    .utilization_fee_earnings
                    .checked_sub(gross_consumed)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                group.header.backing_provider_earnings_total = percolator::V16PodU128::new(
                    group
                        .header
                        .backing_provider_earnings_total
                        .get()
                        .checked_sub(gross_consumed)
                        .ok_or(PercolatorError::EngineCounterUnderflow)?,
                );
            }
            // RESYNC 5ebd136 DUAL withdraw-gate: mirror the source-credit watermark
            // gate from handle_withdraw_backing_bucket. Without it, LP-vault redeem
            // and admin backing-withdraw DIVERGE on the same domain (redeem would
            // hard-set credit_rate_num=CREDIT_RATE_SCALE, bypassing the watermark).
            let mut source_after = source;
            source_after.fresh_reserved_backing_num = source_after
                .fresh_reserved_backing_num
                .checked_sub(backing_num)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            source_after.credit_rate_num =
                expected_source_credit_rate_num(source_after).map_err(map_v16_error)?;
            if source_after.credit_rate_num != percolator::CREDIT_RATE_SCALE {
                return Err(PercolatorError::EngineLockActive.into());
            }
            source = source_after;
            source.credit_epoch = source
                .credit_epoch
                .checked_add(1)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            *source_acc = percolator::SourceCreditStateV16Account::from_runtime(&source);
            *bucket_acc = percolator::BackingBucketV16Account::from_runtime(&bucket);
            // STEP-6 (v17): maintain source_fresh_backing_total_num aggregate.
            // source.fresh_reserved_backing_num dropped by backing_num above;
            // the header aggregate must mirror that delta or validate_header_aggregate_totals
            // (senior + fresh_backing/BOUND_SCALE <= vault) rejects every ExecuteRedemption.
            group.header.source_fresh_backing_total_num = percolator::V16PodU128::new(
                group
                    .header
                    .source_fresh_backing_total_num
                    .get()
                    .checked_sub(backing_num)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?,
            );
            group.header.risk_epoch = percolator::V16PodU64::new(
                group
                    .header
                    .risk_epoch
                    .get()
                    .checked_add(1)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?,
            );
            // Vault decrements by full atoms (principal_portion + earnings_portion)
            // in one operation (principal_portion + earnings_portion). The vault is NOT
            // decremented by the insurance stub (gross_consumed - earnings_portion) —
            // that amount remains in the vault as un-withdrawn insurance reserve.
            // The principal-side fresh-unliened decrement above and the earnings-side
            // backing_provider_earnings_total decrement (by gross_consumed) above keep
            // validate_shape (senior + earnings <= vault) satisfied.
            group.header.vault = percolator::V16PodU128::new(
                group
                    .header
                    .vault
                    .get()
                    .checked_sub(atoms)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?,
            );
            // ── Ledger updates. ──
            // Principal ledger: only principal_portion (NOT earnings_portion).
            ledger.total_principal_atoms = ledger
                .total_principal_atoms
                .checked_sub(principal_portion)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            ledger.total_principal_withdrawn_atoms = ledger
                .total_principal_withdrawn_atoms
                .checked_add(principal_portion)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            // Earnings ledger: book gross_consumed to total_earnings_withdrawn_atoms.
            // This is the GROSS consumed from the earnings pool for this redemption.
            // The fee_share split is preserved: floor((total_earnings - withdrawn_after) *
            // fee_share / 10_000) drops by exactly earnings_portion for remaining LPs.
            //
            // last_observed_bucket_earnings_atoms is a snapshot of
            // bucket.utilization_fee_earnings; we subtract gross_consumed so the next
            // sync_backing_domain_ledger call does not re-credit the consumed chunk.
            if gross_consumed > 0 {
                ledger.last_observed_bucket_earnings_atoms = ledger
                    .last_observed_bucket_earnings_atoms
                    .checked_sub(gross_consumed)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                ledger.total_earnings_withdrawn_atoms = ledger
                    .total_earnings_withdrawn_atoms
                    .checked_add(gross_consumed)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            }
            // LPVAULT-359: the insurance (1 − fee_share) slice of the gross earnings draw —
            //   stub = gross_consumed − earnings_portion
            // was removed from BOTH senior earnings counters (bucket.utilization_fee_earnings
            // and group.header.backing_provider_earnings_total, above) but stays PHYSICALLY in
            // the vault (vault was decremented only by `atoms` = principal_portion +
            // earnings_portion). Until now it was credited to NO header counter, so it sat as an
            // un-owned vault residual that NO withdrawal path could drain — permanently bricking
            // CloseSlab, which gates on vault==0 && insurance==0. Credit it to header.insurance
            // AND the SAME redemption domain's insurance budget (insurance FIRST so the
            // budget-delta guard, which reads header.insurance, admits it), giving the
            // insurance_operator a withdrawable home (WithdrawInsuranceAsset on this domain's
            // asset_index; greedy long-then-short debit drains whichever side holds it) so the
            // reserve drains to zero and teardown proceeds. Vault is UNCHANGED (the stub atoms
            // are already in it); NAV-neutral (LP NAV reads only the backing-domain ledger
            // counters, none of which change here). senior = c_tot + insurance +
            // backing_provider_earnings_total stays <= vault: backing_provider_earnings_total
            // fell by gross_consumed while insurance rose by stub, a net senior drop of
            // earnings_portion (the LP payout that left the vault).
            if gross_consumed > 0 {
                let stub = gross_consumed
                    .checked_sub(earnings_portion)
                    .ok_or(PercolatorError::EngineCounterUnderflow)?;
                if stub > 0 {
                    group.header.insurance = percolator::V16PodU128::new(
                        group
                            .header
                            .insurance
                            .get()
                            .checked_add(stub)
                            .ok_or(PercolatorError::EngineArithmeticOverflow)?,
                    );
                    group
                        .credit_domain_insurance_budget_not_atomic(domain, stub)
                        .map_err(map_v16_error)?;
                }
            }
            group.validate_shape().map_err(map_v16_error)?;
            write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)?;
        }

        // ── Transfer vault → redeemer (vault_authority PDA signs). ──
        let vault_bump_arr = [vault_bump];
        let vault_seeds: &[&[&[u8]]] = &[&[b"vault", market_ai.key.as_ref(), &vault_bump_arr]];
        transfer_tokens_signed(
            token_program,
            vault_token,
            redeemer_dest,
            vault_authority_ai,
            atoms_u64,
            vault_seeds,
        )?;

        // ── Burn the escrowed shares (registry PDA signs as escrow owner). ──
        let shares_u64 = u64::try_from(redemption.shares)
            .map_err(|_| PercolatorError::EngineArithmeticOverflow)?;
        let burn_ix = spl_token::instruction::burn(
            token_program.key,
            escrow_ai.key,
            lp_mint.key,
            &registry_pda,
            &[],
            shares_u64,
        )?;
        invoke_signed(
            &burn_ix,
            &[
                escrow_ai.clone(),
                lp_mint.clone(),
                registry_ai.clone(),
                token_program.clone(),
            ],
            &[&[
                crate::constants::LP_VAULT_REGISTRY_SEED,
                market_ai.key.as_ref(),
                &[registry_bump],
            ]],
        )?;

        // ── Decrement outstanding shares (mirrors the burn). ──
        {
            let mut reg = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
            reg.total_lp_shares_outstanding = reg
                .total_lp_shares_outstanding
                .checked_sub(redemption.shares)
                .ok_or(PercolatorError::EngineCounterUnderflow)?;
            state::write_lp_vault_registry(&mut registry_ai.try_borrow_mut_data()?, &reg)?;
        }

        // ── Consume the redemption PDA (zero magic — replay guard) + reclaim rent. ──
        state::consume_lp_redemption(&mut redemption_ai.try_borrow_mut_data()?)?;
        let reclaim = redemption_ai.lamports();
        **redemption_ai.try_borrow_mut_lamports()? = 0;
        **cranker.try_borrow_mut_lamports()? = cranker
            .lamports()
            .checked_add(reclaim)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(())
    }

    /// LP Vault — CancelRedemption (tag 81).
    ///
    /// Reversal of RequestRedeemLpShares (tag 76): returns the escrowed LP shares
    /// to the recorded redeemer and consumes the LpRedemption PDA. This is the
    /// un-stranding path for a request left in flight when the market leaves Live
    /// (ExecuteRedemption is gated `mode != Live -> EngineLockActive`, so a pending
    /// request can otherwise never be unwound).
    ///
    /// REDEEMER-SIGNED (least privilege): the recorded `redemption.redeemer` must
    /// equal the signer, and the returned shares can only land in that signer's own
    /// LP ATA — no third party can cancel or redirect a redemption.
    ///
    /// MODE-AGNOSTIC: deliberately reads NO market account and touches NO engine /
    /// backing state — only the registry-owned escrow ATA and the redemption PDA.
    /// `total_lp_shares_outstanding` is UNCHANGED (request escrowed the shares
    /// without incrementing it — I2 holds; the symmetric return leaves it untouched).
    ///
    /// DOUBLE-CANCEL / CANCEL-vs-EXECUTE REPLAY GUARD: reads the redemption PDA
    /// first (fails NotInitialized if its magic was already zeroed by a prior
    /// cancel OR by ExecuteRedemption) and consumes it last. Whichever of
    /// {cancel, execute} runs first consumes the PDA; the other fails closed.
    #[inline(never)]
    fn handle_cancel_redemption<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let redeemer = account(accounts, 0)?;
        let registry_ai = account(accounts, 1)?;
        let redemption_ai = account(accounts, 2)?;
        let lp_mint = account(accounts, 3)?;
        let redeemer_lp_ata = account(accounts, 4)?;
        let escrow_ai = account(accounts, 5)?;
        let token_program = account(accounts, 6)?;

        expect_signer(redeemer)?;
        expect_writable(redeemer)?; // rent-reclaim destination
        expect_writable(redemption_ai)?; // consumed
        expect_writable(redeemer_lp_ata)?; // transfer destination
        expect_writable(escrow_ai)?; // transfer source
        expect_owner(registry_ai, program_id)?;
        expect_owner(redemption_ai, program_id)?;
        verify_token_program(token_program)?;

        // ── REPLAY GUARD (read first): NotInitialized if the magic was already
        //    zeroed by a prior cancel OR by ExecuteRedemption. ──
        let redemption = state::read_lp_redemption(&redemption_ai.try_borrow_data()?)?;
        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;

        // ── PDA bindings (no market account is read — mode-agnostic). ──
        let market_key = Pubkey::new_from_array(registry.market_group);
        let (registry_pda, registry_bump) =
            state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        // Canonical redemption PDA for (registry, signer): together with the
        // recorded-redeemer check below, this lets a caller cancel only their OWN
        // request.
        let (redemption_pda, _) =
            state::derive_lp_redemption(program_id, &registry_pda, redeemer.key);
        expect_key(redemption_ai, &redemption_pda)?;
        if redemption.registry != registry_pda.to_bytes() {
            return Err(PercolatorError::LpVaultNotFound.into());
        }
        if redemption.redeemer != redeemer.key.to_bytes() {
            return Err(PercolatorError::Unauthorized.into());
        }
        if lp_mint.key.to_bytes() != registry.lp_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        let (escrow_pda, _) = state::derive_lp_escrow(program_id, &market_key);
        expect_key(escrow_ai, &escrow_pda)?;
        // Destination must be the redeemer's own LP ATA for this mint.
        verify_user_token_account(redeemer_lp_ata, redeemer.key, lp_mint.key)?;

        // ── Return EXACTLY the escrowed shares (registry PDA signs as escrow
        //    owner). The escrow is shared across redeemers, so move only this
        //    redemption's recorded amount — never the full escrow balance. ──
        let shares_u64 = u64::try_from(redemption.shares)
            .map_err(|_| PercolatorError::EngineArithmeticOverflow)?;
        let registry_bump_arr = [registry_bump];
        let registry_seeds: &[&[&[u8]]] = &[&[
            crate::constants::LP_VAULT_REGISTRY_SEED,
            market_key.as_ref(),
            &registry_bump_arr,
        ]];
        transfer_tokens_signed(
            token_program,
            escrow_ai,
            redeemer_lp_ata,
            registry_ai,
            shares_u64,
            registry_seeds,
        )?;

        // total_lp_shares_outstanding UNTOUCHED (request never incremented it).

        // ── Consume the redemption PDA (zero magic — replay guard) + reclaim rent
        //    to the redeemer (the original rent payer at request time). ──
        state::consume_lp_redemption(&mut redemption_ai.try_borrow_mut_data()?)?;
        let reclaim = redemption_ai.lamports();
        **redemption_ai.try_borrow_mut_lamports()? = 0;
        **redeemer.try_borrow_mut_lamports()? = redeemer
            .lamports()
            .checked_add(reclaim)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(())
    }

    /// LP Vault — LpVaultCrankFees (tag 78).
    ///
    /// Permissionless: syncs the backing-domain ledger from the live bucket,
    /// then drains the wrapper-side LP fee counter
    /// (`cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms`) into the LP
    /// vault as REAL, REDEEMABLE BACKING PRINCIPAL.
    ///
    /// PAYS LPs (Task 7 completion, supersedes `d6b4433c`). The first repoint
    /// drained the LP counter into `registry.fee_distribution_total_atoms` — a
    /// statistic that is written and never read — so it moved counters and paid
    /// nobody. LP NAV is
    /// `lp_vault_nav_atoms(total_principal, total_earnings, ...)` (engine
    /// `v16.rs:16473`), so the only wrapper-reachable way to raise an LP's
    /// redeemable claim is to raise `ledger.total_principal_atoms` and back it
    /// with matching `fresh_unliened_backing_num`. That is what this now does.
    ///
    /// THE MECHANISM (Option 1 — zero engine divergence). The LP fee atoms are
    /// already physically inside `header.vault`: the engine credits the whole
    /// trade fee to `header.insurance` at constant vault
    /// (`c_tot -= charged; insurance += charged`, engine `v16.rs:13798`), and
    /// `split_trade_fee` only *earmarks* the LP leg in a wrapper counter. So the
    /// atoms need reclassifying from senior insurance into LP backing, not
    /// moving. `withdraw_insurance_surplus_not_atomic` (engine `v16.rs:7942`)
    /// does exactly `insurance -= a; vault -= a` and moves NO tokens — the
    /// wrapper separately decides whether to CPI a transfer. Restoring
    /// `header.vault` afterwards leaves the tokens in place, and
    /// `add_fresh_counterparty_backing_view` hands them to the LP domain.
    /// Both moves have precedent in `handle_deposit_to_lp_vault`, which
    /// performs the same vault-write + fresh-backing pair:
    ///
    ///   `C + (I−a) + E + (FB+a) = S` against an unchanged `V`
    ///
    /// — byte-identical senior total to the starting state, so `validate_shape`
    /// (and `validate_header_aggregate_totals`) holds with the same slack it had
    /// before. `withdraw_insurance_surplus_not_atomic`'s own internal
    /// `validate_shape` also passes at the intermediate `(V−a, I−a)` point,
    /// because both sides of the inequality drop by exactly `a`.
    ///
    /// Credits `ledger.total_principal_atoms`, NOT `total_deposited_atoms`: no
    /// LP shares are minted, so the same share count now claims more atoms —
    /// which is precisely how the yield reaches existing LPs. `earnings_portion`
    /// therefore stays 0 in `handle_execute_redemption`, which *disarms* rather
    /// than arms the earnings-availability gate defect in that function — the
    /// `if earnings_portion > bucket.utilization_fee_earnings` check, which
    /// tests `earnings_portion` but guards a `gross_consumed` subtraction. Both
    /// are 0 on this path.
    ///
    /// (Cited by line number as `:13889` until the branch-review pass. That
    /// number had drifted onto `handle_execute_redemption`'s `mode !=
    /// MarketModeV16::Live` check — a real gate, so the citation looked correct
    /// and was not. Named rather than renumbered so it cannot rot again.)
    ///
    /// ACCEPTED TRADE-OFF (user decision): LP fee yield lands as at-risk backing
    /// capital, not a senior earnings claim, so it can be impaired by backing
    /// losses between crank and redemption. The alternative — a ~15-line engine
    /// primitive making it senior — was rejected to preserve zero upstream
    /// divergence.
    ///
    /// FEE-SPLIT REPOINT (2026-07-19 design, Task 7). This crank used to key
    /// off `bucket.utilization_fee_earnings` (via the synced ledger's
    /// `total_earnings_atoms`) minus `registry.insurance_fee_snapshot_atoms`.
    /// That source is structurally always 0 on every real market: the backing
    /// utilization fee that feeds it is rate-0 (`backing_trade_fee_bps == 0`,
    /// no instruction sets it) AND is only charged on a lien draw that a
    /// well-capitalized trader never triggers. So tag 78 dead-ended at
    /// `LpVaultNoFeesToCrank` forever and LPs earned nothing. The LP leg of
    /// the trade fee (`cfg.lp_share_bps` of every trade, credited at the two
    /// fee sites) is the real revenue stream, so that is what this drains.
    ///
    /// NO SECOND SPLIT. `registry.fee_share_bps` is deliberately NOT applied
    /// to `available`. That bps splits *bucket* earnings between the LP side
    /// and the insurance-side stub that stays behind in the bucket (see
    /// `percolator::lp_vault::lp_fee_split` / `lp_vault_nav_atoms` Note 3).
    /// `cfg.lp_fee_accrued_atoms` is already the LP-designated leg — the
    /// four-way `split_trade_fee` applied `cfg.lp_share_bps` at the fee site
    /// and routed the insurance leg to `cfg.insurance_reserve_accrued_atoms`
    /// separately. Re-splitting here would strand
    /// `(1 - fee_share_bps/10_000) * available` with no destination and no
    /// counter, and would force `lp_fee_withdrawn_atoms` to advance by more
    /// than was actually credited. The whole of `available` is credited and
    /// exactly the whole of `available` is marked withdrawn.
    ///
    /// MANDATORY CLAMP. The protocol leg (tag 84 `WithdrawProtocolFee` — NOT
    /// tag 83, which is `InitMatcherCtx`), this LP leg, and the stake
    /// leg now ALL draw from one pool: `insurance − source_insurance_credit_
    /// reserved_total_atoms − insurance_domain_budget_remaining_total`. Nothing
    /// checks that the three wrapper-side counters sum within it, so whichever
    /// leg cranks last would get `EngineLockActive` out of the engine unless
    /// each clamps its own claim first. This mirrors the `§1.3/N2 clamp` in
    /// `handle_withdraw_protocol_fee` and then advances
    /// `lp_fee_withdrawn_atoms` by the CLAMPED amount actually applied, never
    /// the requested amount — so a partial fill leaves the remainder claimable
    /// on the next crank instead of marking it paid without paying it.
    #[inline(never)]
    fn handle_lp_vault_crank_fees<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        target_domain: u16,
    ) -> ProgramResult {
        let cranker = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let own_ledger_ai = account(accounts, 3)?;
        // The vault's OTHER domain ledger, plus system_program so whichever pot
        // is targeted can have its ledger created on first arrival. Once deposits
        // can be routed (tag 75), a vault whose money all went to the sibling has
        // NO own-domain ledger, and an unconditional `expect_owner` on it bricked
        // the crank outright.
        let sibling_ledger_ai = account(accounts, 4)?;
        let system_program_ai = account(accounts, 5)?;
        expect_signer(cranker)?;
        expect_writable(cranker)?;
        expect_writable(market_ai)?;
        expect_writable(registry_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;
        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        let market_key = Pubkey::new_from_array(registry.market_group);
        expect_key(market_ai, &market_key)?;
        let (registry_pda, _) = state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        if target_domain as usize / 2 != registry.domain as usize / 2 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let (own_ledger_pda, own_ledger_bump) =
            state::derive_lp_backing_ledger(program_id, &market_key, registry.domain);
        expect_key(own_ledger_ai, &own_ledger_pda)?;
        let (sibling_ledger_pda, sibling_ledger_bump) = state::derive_lp_backing_ledger(
            program_id,
            &market_key,
            sibling_domain(registry.domain),
        );
        expect_key(sibling_ledger_ai, &sibling_ledger_pda)?;
        // Both candidates are address-pinned, so this selection is not caller-steerable.
        let (ledger_ai, ledger_bump) = if target_domain == registry.domain {
            (own_ledger_ai, own_ledger_bump)
        } else {
            (sibling_ledger_ai, sibling_ledger_bump)
        };
        expect_writable(ledger_ai)?;
        if ledger_ai.data_is_empty() {
            let len = state::backing_domain_ledger_account_len();
            let target_domain_bytes = target_domain.to_le_bytes();
            let ledger_bump_bytes = [ledger_bump];
            let ledger_seeds: &[&[u8]] = &[
                crate::constants::LP_BACKING_LEDGER_SEED,
                market_ai.key.as_ref(),
                target_domain_bytes.as_ref(),
                ledger_bump_bytes.as_ref(),
            ];

            create_pda_account(
                cranker,
                ledger_ai,
                system_program_ai,
                len,
                program_id,
                ledger_seeds,
            )?;
        }
        expect_owner(ledger_ai, program_id)?;
        let domain = target_domain as usize;

        // ORPHANED-ATOMS GUARD (Finding 3). The crank moves atoms out of
        // `header.insurance` and into `ledger.total_principal_atoms` +
        // `bucket.fresh_unliened_backing_num`, where they are claimable ONLY
        // pro rata by LP shares. After the last real LP redeems, outstanding
        // falls back to the irreducible `LP_VAULT_MINIMUM_LIQUIDITY` dead-share
        // floor (never minted, never redeemable -- see BUG-2/N7 on
        // `handle_deposit_to_lp_vault`) and the SPL mint supply returns to 0.
        // `add_fresh_counterparty_backing_view` happily accepts an `Empty` or
        // `Expired` bucket, so without this check a permissionless crank on a
        // fully-exited vault credits principal that NO share can ever claim,
        // and `handle_close_lp_vault` -- which inspects only shares and mint
        // supply, never the backing ledger -- then tears the registry down with
        // that principal stranded inside it. No solvency break, but the atoms
        // leave the insurance fund and belong to nobody.
        //
        // Error choice: NOT `LpVaultNoFeesToCrank` (38) -- fees demonstrably DO
        // exist here, and reporting "no fees" would send an operator hunting for
        // a missing accrual instead of a missing LP. `LpVaultZeroSharesMinted`
        // (41) is the existing variant for exactly this invariant:
        // `handle_deposit_to_lp_vault` raises it to refuse to absorb value when
        // the operation would leave zero real shares behind it. Same failure mode,
        // same remedy (deposit first) -- value in, no shares to claim it. No new
        // variant is warranted.
        if registry.total_lp_shares_outstanding <= crate::constants::LP_VAULT_MINIMUM_LIQUIDITY {
            return Err(PercolatorError::LpVaultZeroSharesMinted.into());
        }

        // Sync the ledger from the live bucket, persist, read current earnings,
        // and compute/consume the wrapper-side LP fee claim.
        let (total_earnings, available, cfg_after) = {
            let mut market_data = market_ai.try_borrow_mut_data()?;
            let (mut cfg, mut group) = state::market_view_mut(&mut market_data)?;
            // MODE GATE (Finding 1) -- modelled on `handle_deposit_to_lp_vault`
            // mode gate, NOT on `handle_withdraw_protocol_fee`'s `live_mode`
            // / `resolved_mode` block, and deliberately the STRICTER of the two.
            //
            // Rationale. What this crank does is functionally a DEPOSIT into the
            // LP backing domain: it calls the same
            // `add_fresh_counterparty_backing_view` with the same
            // `LP_VAULT_BACKING_EXPIRY_SLOT` and credits the same
            // `ledger.total_principal_atoms`. It differs from a real deposit only
            // in where the atoms come from (senior insurance rather than the
            // depositor's token account) and in that NOBODY has to authorise it --
            // tag 78 carries no authority signature at all, only
            // `expect_signer(cranker)` on an arbitrary fee payer. A handler that
            // anyone can fire at any moment should not be reachable in more market
            // states than the same operation performed by its own beneficiary.
            //
            // Why not the protocol-fee model. `handle_withdraw_protocol_fee` may
            // run in Resolved because it (a) requires the protocol fee authority's
            // signature, and (b) EXTINGUISHES the claim -- atoms leave to an
            // authority-owned token account and no downstream obligation survives,
            // which is why the `materialized_portfolio_count == 0 && c_tot == 0`
            // precondition is sufficient there. This crank does the opposite: it
            // CONVERTS senior insurance into a junior LP claim that must still be
            // paid out later through `RequestRedeemLpShares` -> `ExecuteRedemption`.
            // "Safe to drain now" therefore does not transfer, and creating fresh
            // backing on a market that is winding down is meaningless.
            //
            // Concretely blocked:
            //   * Recovery (mode 2) -- the failure in the finding. Post-solvency-
            //     event, `header.insurance` IS the recovery buffer; any signer
            //     could otherwise convert up to `lp_fee_accrued - lp_fee_withdrawn`
            //     of it into junior LP backing and have LPs redeem it out.
            //   * Resolved (mode 1) -- same conversion, before trader portfolios
            //     are materialised.
            //   * Live-but-matured -- `reject_permissionless_resolve_matured_live_view`
            //     is what `handle_deposit_to_lp_vault` uses to stop permissionless
            //     writes to a market that is past its stale-resolve horizon and is
            //     merely awaiting someone to resolve it.
            //
            // The claim is NOT lost in any of these states: nothing is marked
            // withdrawn on a rejected crank, so `lp_fee_accrued - lp_fee_withdrawn`
            // stays fully claimable if the market returns to Live.
            if group.header.mode != 0 {
                return Err(PercolatorError::EngineLockActive.into());
            }
            reject_permissionless_resolve_matured_live_view(&cfg, &group)?;
            // PROG-1: verify the vault is still the backing authority for this domain.
            // handle_deposit_to_lp_vault and handle_execute_redemption both enforce this;
            // without the check here, a fee crank after an asset_admin authority rotation
            // inflates insurance_fee_snapshot_atoms with earnings the vault does not own,
            // causing LP holders to lose claim to fees in the gap when authority is restored.
            let authorities = domain_authorities_from_view(&group, &cfg, domain)?;
            if authorities.backing_bucket_authority != registry_pda.to_bytes() {
                return Err(PercolatorError::LpVaultAuthorityMismatch.into());
            }
            let (_, bucket) = backing_domain_parts_view(&group, domain)?;
            let mut ledger_data = ledger_ai.try_borrow_mut_data()?;
            let (mut ledger, initialized) = read_or_new_backing_domain_ledger(
                &ledger_data,
                market_ai.key.to_bytes(),
                registry_pda.to_bytes(),
                target_domain,
                &bucket,
            )?;
            sync_backing_domain_ledger(&mut ledger, &bucket)?;
            let te = ledger.total_earnings_atoms;

            // Claim capacity. Monotonic invariant:
            // lp_fee_withdrawn_atoms <= lp_fee_accrued_atoms, always — so the
            // subtraction can only underflow on a corrupt config, which fails
            // closed.
            // #411: computed by `lp_vault_harvestable_fee_atoms`, which
            // `handle_deposit_to_lp_vault` also calls. Deliberately shared — a deposit must
            // be priced against exactly what a crank in the same slot would realize, and
            // two separate copies of this clamp would drift and reopen that bug. The
            // reasoning that used to live here (three legs share one surplus pool with no
            // cross-leg accounting, so an unclamped claim makes the last leg to crank fail
            // out of the engine) now lives on the helper.
            let available = lp_vault_harvestable_fee_atoms(&cfg, &group)?;
            // Zero case: nothing accrued, or the surplus pool is currently dry
            // (another leg got there first). Same error either way — the claim
            // is NOT marked withdrawn, so it stays fully claimable next crank.
            if available == 0 {
                return Err(PercolatorError::LpVaultNoFeesToCrank.into());
            }

            // ── Reclassify `available` atoms: senior insurance → LP backing. ──
            // No token moves. See the MECHANISM block on this handler.
            let v_before = group.header.vault.get();
            group
                .withdraw_insurance_surplus_not_atomic(available) // I−a, V−a
                .map_err(map_v16_error)?;
            group.header.vault = percolator::V16PodU128::new(v_before); // restore V
            add_fresh_counterparty_backing_view(
                &mut group,
                domain,
                available
                    .checked_mul(BOUND_SCALE)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?, // FB += a·BOUND_SCALE
                crate::constants::LP_VAULT_BACKING_EXPIRY_SLOT,
            )?;
            // #413: re-baseline before booking the principal — same reasoning as the
            // deposit and rebalance paths. The refill above lowers
            // `consumed_liened_backing_num`, and the NEXT sync would otherwise read that
            // drop as `cumulative_recovery_atoms` while these same atoms are also being
            // added as principal directly below. The sync at the top of this handler ran
            // against the pre-refill bucket, so pinning the watermark here is what keeps
            // the two from counting the same value twice.
            {
                let (_, bucket_after) = backing_domain_parts_view(&group, domain)?;
                ledger.last_observed_unavailable_principal_atoms =
                    backing_unavailable_principal_atoms(&bucket_after)?;
            }
            // The LP-visible half: same shares, more principal ⇒ higher NAV ⇒ a
            // strictly larger redeemable claim for every existing LP.
            ledger.total_principal_atoms = ledger
                .total_principal_atoms
                .checked_add(available)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            // Conservation: C + (I−a) + E + (FB+a) = S against an unchanged V.
            group.validate_shape().map_err(map_v16_error)?;
            write_or_init_backing_domain_ledger(&mut ledger_data, &ledger, initialized)?;

            // Mark withdrawn by exactly the CLAMPED `available` that was just
            // applied — never `claim_capacity`. A clamped (partial) crank leaves
            // `claim_capacity - available` claimable on the next crank rather
            // than marking it paid without paying it.
            cfg.lp_fee_withdrawn_atoms = cfg
                .lp_fee_withdrawn_atoms
                .checked_add(available)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            (te, available, cfg)
        };

        {
            let mut reg = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
            reg.insurance_fee_snapshot_atoms = total_earnings;
            reg.fee_distribution_total_atoms = reg
                .fee_distribution_total_atoms
                .checked_add(available)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
            state::write_lp_vault_registry(&mut registry_ai.try_borrow_mut_data()?, &reg)?;
        }
        // CRITICAL write-back. Unconditional on this path: every successful
        // call mutates `lp_fee_withdrawn_atoms` (a zero-`available` crank
        // returned Err above, and a failed instruction rolls every account
        // write back). Without it the counter resets and the SAME atoms are
        // credited to `fee_distribution_total_atoms` again on the next crank.
        // Mirrors `handle_withdraw_protocol_fee`'s unconditional write-back
        // rather than the trade-fee sites' opt-in `cfg_after` pattern.
        state::write_wrapper_config(&mut market_ai.try_borrow_mut_data()?, &cfg_after)?;
        Ok(())
    }

    /// LP Vault — SetLpVaultPaused (tag 79).
    ///
    /// marketauth-gated. Paused vaults reject DepositToLpVault and
    /// RequestRedeemLpShares (ExecuteRedemption + CloseLpVault still allowed).
    #[inline(never)]
    fn handle_set_lp_vault_paused<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        paused: u8,
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        expect_signer(admin)?;
        expect_writable(registry_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;
        if paused > 1 {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let mut registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        let market_key = Pubkey::new_from_array(registry.market_group);
        expect_key(market_ai, &market_key)?;
        let (registry_pda, _) = state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        let (cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        // v17: cfg.marketauth replaces cfg.admin.
        if admin.key.to_bytes() != cfg.marketauth {
            return Err(PercolatorError::Unauthorized.into());
        }
        registry.paused = paused;
        state::write_lp_vault_registry(&mut registry_ai.try_borrow_mut_data()?, &registry)?;
        Ok(())
    }

    /// LP Vault — CloseLpVault (tag 80).
    ///
    /// marketauth-gated. Requires zero outstanding shares (registry counter AND
    /// the live LP mint supply — I2 defense). Closes the registry PDA (zero
    /// data + reclaim rent). The LP mint is left on-chain at supply 0.
    #[inline(never)]
    fn handle_close_lp_vault<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let lp_mint = account(accounts, 3)?;
        expect_signer(admin)?;
        expect_writable(admin)?;
        expect_writable(registry_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(registry_ai, program_id)?;

        let registry = state::read_lp_vault_registry(&registry_ai.try_borrow_data()?)?;
        // BUG-2 / N7: a vault that ever took a genesis deposit permanently carries
        // LP_VAULT_MINIMUM_LIQUIDITY of "outstanding" shares that were counted in
        // total_lp_shares_outstanding at genesis but never minted to any account
        // (see handle_deposit_to_lp_vault) — they can never be redeemed/burned back
        // out, by design (the dead-share anti-inflation floor). So "fully redeemed"
        // now means outstanding <= LP_VAULT_MINIMUM_LIQUIDITY (the irreducible
        // floor), not strictly `== 0`. A vault that never received any deposit has
        // outstanding == 0, which still satisfies this bound. The SPL mint's live
        // `supply` check below is UNCHANGED and remains a strict `!= 0` reject: the
        // dead-share floor was never minted, so real supply still returns to
        // exactly 0 once every actual depositor has redeemed — that check alone
        // would NOT have caught a vault with only-dead-shares-outstanding, which is
        // why both checks are still needed together.
        if registry.total_lp_shares_outstanding > crate::constants::LP_VAULT_MINIMUM_LIQUIDITY {
            return Err(PercolatorError::LpVaultSharesOutstanding.into());
        }
        let market_key = Pubkey::new_from_array(registry.market_group);
        expect_key(market_ai, &market_key)?;
        let (registry_pda, _) = state::derive_lp_vault_registry(program_id, &market_key);
        expect_key(registry_ai, &registry_pda)?;
        if lp_mint.key.to_bytes() != registry.lp_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        let (cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        // v17: cfg.marketauth replaces cfg.admin.
        if admin.key.to_bytes() != cfg.marketauth {
            return Err(PercolatorError::Unauthorized.into());
        }
        // Defense-in-depth (I2): live SPL mint supply must also be zero.
        {
            let mint_data = lp_mint.try_borrow_data()?;
            let mint = spl_token::state::Mint::unpack(&mint_data)?;
            if mint.supply != 0 {
                return Err(PercolatorError::LpVaultSharesOutstanding.into());
            }
        }
        // Close the registry PDA: zero data + reclaim rent to admin.
        {
            let mut data = registry_ai.try_borrow_mut_data()?;
            for b in data.iter_mut() {
                *b = 0;
            }
        }
        let reclaim = registry_ai.lamports();
        **registry_ai.try_borrow_mut_lamports()? = 0;
        **admin.try_borrow_mut_lamports()? = admin
            .lamports()
            .checked_add(reclaim)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(())
    }

    // ── Fork NFT / B-3 (tags 72/73) ──────────────────────────────────────────
    //
    // SetNftProgramId (tag 73): marketauth-gated, creates or updates the
    // NftRegistry PDA.
    //
    // TransferPortfolioOwnership (tag 72): CPI-ONLY from the registered NFT
    // program's mint-authority PDA.
    //
    // Security design: all 6 guardrails from nft_design.md §7 implemented.
    // Fund-critical: under-gated = portfolio theft.
    //
    // Guardrail 5 (trust boundary): the wrapper trusts the PDA-signing NFT
    // program (proven via Guardrail 1); does NOT re-check holdership.
    //
    // Guardrail 6 (conservation): owner-field rewrite only; zero token/stock/
    // lien movement.
    //
    // v17 delta vs original fork: cfg.admin → cfg.marketauth for SetNftProgramId.

    /// B-3 core: pure function writing both owner fields atomically.
    ///
    /// Implements Guardrails 2 (atomic dual-write), 3 (state gating),
    /// 4 (no-op/self-transfer).
    pub fn b3_check_and_rewrite_owner(
        p: &mut percolator::PortfolioAccountV16Account,
        new_owner: [u8; 32],
        asset_index: u16,
    ) -> Result<(), ProgramError> {
        // ── Guardrail 4 (no-op / self-transfer) ─────────────────────────────
        if new_owner == [0u8; 32] {
            return Err(PercolatorError::NftTransferSelfOrZero.into());
        }
        if new_owner == p.owner {
            return Err(PercolatorError::NftTransferSelfOrZero.into());
        }

        // ── Guardrail 3 (state gating) ───────────────────────────────────────
        let asset_index_u32 = asset_index as u32;
        let leg_slot: Option<&percolator::PortfolioLegV16Account> = {
            let mut found = None;
            let mut i = 0usize;
            while i < percolator::V16_MAX_PORTFOLIO_ASSETS_N {
                let leg = &p.legs[i];
                if leg.active != 0 && leg.asset_index.get() == asset_index_u32 {
                    found = Some(leg);
                    break;
                }
                i += 1;
            }
            found
        };
        let leg = leg_slot.ok_or(PercolatorError::NftPortfolioNotTransferable)?;

        if p.liquidation_lock != 0 || p.stale_state != 0 || p.b_stale_state != 0 {
            return Err(PercolatorError::NftPortfolioNotTransferable.into());
        }
        if p.resolved_payout_receipt.present != 0 {
            return Err(PercolatorError::NftPortfolioNotTransferable.into());
        }
        if p.close_progress.active != 0
            && p.close_progress.asset_index.get() == asset_index_u32
        {
            return Err(PercolatorError::NftPortfolioNotTransferable.into());
        }
        if leg.b_stale != 0 || leg.stale != 0 {
            return Err(PercolatorError::NftPortfolioNotTransferable.into());
        }

        // ── Guardrail 2 (atomic dual-write) ──────────────────────────────────
        p.owner = new_owner;
        p.provenance_header.owner = new_owner;
        debug_assert_eq!(
            p.owner,
            p.provenance_header.owner,
            "b3: dual-write invariant violated"
        );
        debug_assert_eq!(p.owner, new_owner, "b3: owner not written");
        Ok(())
    }

    /// UnwrapEscrowedPortfolio core (tag 82): release an NFT-escrowed portfolio
    /// back to the burning holder. Pure function — owner-field rewrite only.
    ///
    /// `current_escrow` is the calling NFT program's mint-authority PDA (derived
    /// by the handler from the registry's `nft_program_id`). The portfolio MUST
    /// currently be owned by it: this is the escrow invariant, and the ONLY gate.
    ///
    /// Deliberately NOT gated on active-leg / `resolved_payout_receipt.present` /
    /// `liquidation_lock` / stale / close-progress: an escrowed position may be
    /// closed, liquidated, or resolved while wrapped, and the holder must always
    /// be able to reclaim ownership to recover residual collateral or a resolved
    /// payout (gating on those would strand funds — the exact failure mode
    /// escrow-at-mint must avoid). Releasing the owner mid-settlement is safe:
    /// every downstream owner-gated instruction (Withdraw, CloseResolved, …)
    /// keeps its own stale/lock gating, so this grants no capability the holder
    /// could not safely exercise once those clear.
    ///
    /// Conservation (B-3 Guardrail 6, unchanged): owner-field rewrite only; zero
    /// token / stock / lien / capital movement.
    pub fn unwrap_check_and_rewrite_owner(
        p: &mut percolator::PortfolioAccountV16Account,
        new_owner: [u8; 32],
        current_escrow: [u8; 32],
    ) -> Result<(), ProgramError> {
        // new_owner must be a real (non-zero) wallet.
        if new_owner == [0u8; 32] {
            return Err(PercolatorError::NftTransferSelfOrZero.into());
        }
        // Escrow invariant: only release a position THIS NFT program escrowed.
        // (A normally-owned portfolio has owner != the NFT program PDA, so this
        // can never seize one; and the handler already proved, via the signing
        // mint-authority PDA + registry, that the caller IS that NFT program.)
        if p.owner != current_escrow {
            return Err(PercolatorError::NftPortfolioNotTransferable.into());
        }
        // current_escrow is a program PDA (off-curve, no key); a holder wallet
        // can never equal it, so new_owner != p.owner is implied. Reject the
        // degenerate equal case anyway for strictness.
        if new_owner == p.owner {
            return Err(PercolatorError::NftTransferSelfOrZero.into());
        }
        p.owner = new_owner;
        p.provenance_header.owner = new_owner;
        debug_assert_eq!(
            p.owner,
            p.provenance_header.owner,
            "unwrap: dual-write invariant violated"
        );
        debug_assert_eq!(p.owner, new_owner, "unwrap: owner not written");
        Ok(())
    }

    /// SetNftProgramId (tag 73) — creates or updates the per-market NftRegistry PDA.
    ///
    /// Accounts:
    ///   0  admin        [signer, writable] — pays rent on create
    ///   1  market       [ro]               — source of cfg.marketauth + key for PDA
    ///   2  nft_registry [writable, PDA]    — `["nft_registry", market.key]`
    ///   3  system_program
    #[inline(never)]
    fn handle_set_nft_program_id<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        nft_program_id: [u8; 32],
    ) -> ProgramResult {
        let admin = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;
        let system_program_ai = account(accounts, 3)?;

        expect_signer(admin)?;
        expect_writable(admin)?;
        expect_writable(registry_ai)?;
        expect_owner(market_ai, program_id)?;

        if system_program_ai.key != &system_program::ID {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if nft_program_id == [0u8; 32] {
            return Err(PercolatorError::InvalidInstruction.into());
        }

        // v17: cfg.marketauth replaces cfg.admin.
        let (cfg, _, _, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        if admin.key.to_bytes() != cfg.marketauth {
            return Err(PercolatorError::Unauthorized.into());
        }

        let (expected_pda, bump) = state::derive_nft_registry(program_id, market_ai.key);
        expect_key(registry_ai, &expected_pda)?;

        if registry_ai.owner == &system_program::ID && registry_ai.data_is_empty() {
            // CREATE path.
            let registry_len = state::nft_registry_account_len();
            let market_bytes = market_ai.key.to_bytes();
            let bump_bytes = [bump];
            let registry_seeds: &[&[u8]] = &[
                crate::constants::NFT_REGISTRY_SEED,
                market_bytes.as_ref(),
                bump_bytes.as_ref(),
            ];

            create_pda_account(
                admin,
                registry_ai,
                system_program_ai,
                registry_len,
                program_id,
                registry_seeds,
            )?;
            let new_reg = state::NftRegistryV16 {
                market_group: market_ai.key.to_bytes(),
                nft_program_id,
                version: crate::constants::NFT_REGISTRY_VERSION,
                bump,
                _padding: [0u8; 6],
            };
            state::init_nft_registry(&mut registry_ai.try_borrow_mut_data()?, &new_reg)?;
        } else {
            // SECURITY (set-once): registry.nft_program_id is the custody trust
            // root for this market — handle_transfer_portfolio_ownership derives
            // its sole trusted mint-authority PDA from it, and B-3 has no
            // portfolio<->NFT-mint binding. Allowing a single marketauth key to
            // re-point it would let that key (or a compromise of it) swap the
            // trust root to an attacker-controlled program and seize every
            // portfolio in the market. The program id is therefore immutable
            // after the first set: only the CREATE path above is permitted, and
            // any subsequent SetNftProgramId is rejected. A market that must run
            // a different NFT program is stood up fresh; a buggy NFT program can
            // still be fixed in place via a program upgrade (the registry pins a
            // program id, not a code hash).
            return Err(PercolatorError::AlreadyInitialized.into());
        }
        Ok(())
    }

    /// B-3 TransferPortfolioOwnership (tag 72).
    ///
    /// CPI-ONLY — the NFT program's `ExecuteTransferHook` calls this with its
    /// `mint_authority` PDA as the signer.
    ///
    /// Accounts:
    ///   0  mint_auth    [signer]           — NFT program's mint-authority PDA
    ///   1  portfolio    [writable]         — portfolio being transferred
    ///   2  nft_registry [ro, PDA]          — `["nft_registry", market_group]`
    ///
    /// All 6 §7 guardrails implemented (see module-level comment).
    #[inline(never)]
    fn handle_transfer_portfolio_ownership<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        new_owner: [u8; 32],
        asset_index: u16,
    ) -> ProgramResult {
        let mint_auth_ai = account(accounts, 0)?;
        let portfolio_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;

        // ── Guardrail 1 (auth + registry, FAIL-CLOSED) ──────────────────────
        expect_signer(mint_auth_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(portfolio_ai, program_id)?;

        // Validate portfolio header.
        {
            let data = portfolio_ai.try_borrow_data()?;
            state::check_portfolio_kind(&data)?;
        }

        // Read portfolio POD to get market_group_id for registry binding.
        let market_group_bytes: [u8; 32] = {
            let data = portfolio_ai.try_borrow_data()?;
            let wire = state::portfolio_wire(&data)?;
            wire.provenance_header
                .try_to_runtime()
                .map_err(|_| PercolatorError::NftPortfolioProvenance)?;
            if wire.provenance_header.portfolio_account_id != portfolio_ai.key.to_bytes() {
                return Err(PercolatorError::NftPortfolioProvenance.into());
            }
            wire.provenance_header.market_group_id
        };

        // Read NftRegistry — FAIL-CLOSED: uninitialized = NftRegistryNotFound.
        let market_group_key = Pubkey::new_from_array(market_group_bytes);
        let (expected_registry_pda, _) =
            state::derive_nft_registry(program_id, &market_group_key);
        expect_key(registry_ai, &expected_registry_pda)?;
        expect_owner(registry_ai, program_id)?;

        let registry = state::read_nft_registry(&registry_ai.try_borrow_data()?)
            .map_err(|_| PercolatorError::NftRegistryNotFound)?;
        if registry.market_group != market_group_bytes {
            return Err(PercolatorError::NftRegistryNotFound.into());
        }

        // Derive expected mint-authority PDA from the registered NFT program.
        let nft_program_id = Pubkey::new_from_array(registry.nft_program_id);
        let (expected_mint_auth, _) = state::derive_nft_mint_authority(&nft_program_id);
        if mint_auth_ai.key != &expected_mint_auth {
            return Err(PercolatorError::NftInvalidMintAuthority.into());
        }

        // ── Guardrails 2/3/4 via pure function ──────────────────────────────
        {
            let mut data = portfolio_ai.try_borrow_mut_data()?;
            let p = state::portfolio_wire_mut(&mut data)?;
            b3_check_and_rewrite_owner(p, new_owner, asset_index)?;
            debug_assert_eq!(
                p.owner,
                p.provenance_header.owner,
                "b3 handler: dual-write invariant violated"
            );
        }
        Ok(())
    }

    /// UnwrapEscrowedPortfolio (tag 82).
    ///
    /// CPI-ONLY — the NFT program's Burn/EmergencyBurn handlers call this with
    /// their mint-authority PDA as the signer, to release escrow-at-mint custody
    /// (#105) back to the burning holder. The auth block is identical to B-3
    /// (tag 72): the wrapper trusts the PDA-signing registered NFT program
    /// (Guardrail 1/5) and does not re-check NFT holdership — the NFT program
    /// proves it before calling. The release itself is gated only on the escrow
    /// invariant (`portfolio.owner == this NFT program's mint-authority PDA`).
    ///
    /// Accounts (same shape as B-3 tag 72):
    ///   0  mint_auth    [signer]   — NFT program's mint-authority PDA (== escrow owner)
    ///   1  portfolio    [writable] — escrowed portfolio being released
    ///   2  nft_registry [ro, PDA]  — `["nft_registry", market_group]`
    #[inline(never)]
    fn handle_unwrap_escrowed_portfolio<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        new_owner: [u8; 32],
    ) -> ProgramResult {
        let mint_auth_ai = account(accounts, 0)?;
        let portfolio_ai = account(accounts, 1)?;
        let registry_ai = account(accounts, 2)?;

        // ── Auth + registry (FAIL-CLOSED) — identical to B-3 ────────────────
        expect_signer(mint_auth_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(portfolio_ai, program_id)?;

        {
            let data = portfolio_ai.try_borrow_data()?;
            state::check_portfolio_kind(&data)?;
        }

        let market_group_bytes: [u8; 32] = {
            let data = portfolio_ai.try_borrow_data()?;
            let wire = state::portfolio_wire(&data)?;
            wire.provenance_header
                .try_to_runtime()
                .map_err(|_| PercolatorError::NftPortfolioProvenance)?;
            if wire.provenance_header.portfolio_account_id != portfolio_ai.key.to_bytes() {
                return Err(PercolatorError::NftPortfolioProvenance.into());
            }
            wire.provenance_header.market_group_id
        };

        let market_group_key = Pubkey::new_from_array(market_group_bytes);
        let (expected_registry_pda, _) =
            state::derive_nft_registry(program_id, &market_group_key);
        expect_key(registry_ai, &expected_registry_pda)?;
        expect_owner(registry_ai, program_id)?;

        let registry = state::read_nft_registry(&registry_ai.try_borrow_data()?)
            .map_err(|_| PercolatorError::NftRegistryNotFound)?;
        if registry.market_group != market_group_bytes {
            return Err(PercolatorError::NftRegistryNotFound.into());
        }

        // Derive expected mint-authority PDA from the registered NFT program;
        // this is BOTH the required signer AND the escrow owner the portfolio
        // must currently have.
        let nft_program_id = Pubkey::new_from_array(registry.nft_program_id);
        let (expected_mint_auth, _) = state::derive_nft_mint_authority(&nft_program_id);
        if mint_auth_ai.key != &expected_mint_auth {
            return Err(PercolatorError::NftInvalidMintAuthority.into());
        }

        // ── Release escrow (owner-only rewrite, escrow-invariant gated) ──────
        {
            let mut data = portfolio_ai.try_borrow_mut_data()?;
            let p = state::portfolio_wire_mut(&mut data)?;
            unwrap_check_and_rewrite_owner(p, new_owner, expected_mint_auth.to_bytes())?;
            debug_assert_eq!(
                p.owner,
                p.provenance_header.owner,
                "unwrap handler: dual-write invariant violated"
            );
        }
        Ok(())
    }

    // ── LP Vault helper functions ─────────────────────────────────────────────
    //
    // These are private to the processor module; identical logic to the original
    // fork but using percolator::wide_math (fork-facade re-export) for U256.

    fn source_credit_available_backing_num(
        state: SourceCreditStateV16,
    ) -> Result<u128, V16Error> {
        if state.fresh_reserved_backing_num < state.valid_liened_backing_num
            || state.spent_backing_num < state.provider_receivable_num
        {
            return Err(V16Error::InvalidConfig);
        }
        let insurance_encumbered = state
            .valid_liened_insurance_num
            .checked_add(state.impaired_liened_insurance_num)
            .ok_or(V16Error::ArithmeticOverflow)?;
        if state.insurance_credit_reserved_num < insurance_encumbered {
            return Err(V16Error::InvalidConfig);
        }
        state
            .fresh_reserved_backing_num
            .checked_sub(state.valid_liened_backing_num)
            .and_then(|v| {
                v.checked_add(state.insurance_credit_reserved_num - insurance_encumbered)
            })
            .ok_or(V16Error::ArithmeticOverflow)
    }

    fn expected_source_credit_rate_num(
        state: SourceCreditStateV16,
    ) -> Result<u128, V16Error> {
        if state.exact_positive_claim_num > state.positive_claim_bound_num
            || state.credit_rate_num > percolator::CREDIT_RATE_SCALE
        {
            return Err(V16Error::InvalidConfig);
        }
        if state.positive_claim_bound_num == 0 {
            source_credit_available_backing_num(state)?;
            return Ok(percolator::CREDIT_RATE_SCALE);
        }
        let available = source_credit_available_backing_num(state)?;
        let rate = percolator::wide_math::U256::from_u128(available)
            .checked_mul(percolator::wide_math::U256::from_u128(
                percolator::CREDIT_RATE_SCALE,
            ))
            .and_then(|v| {
                v.checked_div(percolator::wide_math::U256::from_u128(
                    state.positive_claim_bound_num,
                ))
            })
            .and_then(|v| v.try_into_u128())
            .ok_or(V16Error::ArithmeticOverflow)?;
        Ok(core::cmp::min(rate, percolator::CREDIT_RATE_SCALE))
    }

    fn add_fresh_counterparty_backing_view(
        group: &mut state::MarketViewMutV16<'_>,
        domain: usize,
        amount_num: u128,
        expiry_slot: u64,
    ) -> ProgramResult {
        let max_markets = group.header.config.max_market_slots.get() as usize;
        let asset_index = domain / 2;
        if domain >= max_markets.saturating_mul(2)
            || asset_index >= group.markets.len()
            || amount_num == 0
            || expiry_slot <= group.header.current_slot.get()
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let slot = &mut group.markets[asset_index].engine;
        let (source_acc, bucket_acc) = if domain % 2 == 0 {
            (&mut slot.source_credit_long, &mut slot.backing_long)
        } else {
            (&mut slot.source_credit_short, &mut slot.backing_short)
        };
        let mut source = source_acc.try_to_runtime().map_err(map_v16_error)?;
        let mut bucket = bucket_acc.try_to_runtime().map_err(map_v16_error)?;
        if source.provider_receivable_num != bucket.consumed_liened_backing_num
            || source.spent_backing_num < source.provider_receivable_num
        {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        match bucket.status {
            BackingBucketStatusV16::Empty | BackingBucketStatusV16::Expired => {
                bucket.status = BackingBucketStatusV16::Fresh;
                bucket.expiry_slot = expiry_slot;
            }
            BackingBucketStatusV16::Fresh if bucket.expiry_slot == expiry_slot => {}
            _ => return Err(PercolatorError::EngineLockActive.into()),
        }
        let refill = core::cmp::min(amount_num, source.provider_receivable_num);
        if refill > bucket.consumed_liened_backing_num {
            return Err(PercolatorError::EngineCounterUnderflow.into());
        }
        bucket.consumed_liened_backing_num -= refill;
        source.provider_receivable_num -= refill;
        bucket.fresh_unliened_backing_num = bucket
            .fresh_unliened_backing_num
            .checked_add(amount_num)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        source.fresh_reserved_backing_num = source
            .fresh_reserved_backing_num
            .checked_add(amount_num)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        // STEP-6 (v17): keep header aggregate in sync with per-domain delta.
        // add_fresh_counterparty_backing_view is the wrapper's inline substitute for
        // the engine's set_source_credit_for_domain which calls
        // update_source_credit_aggregate_totals. Without this maintenance,
        // validate_header_aggregate_totals (senior + fresh_backing/BOUND_SCALE <= vault)
        // rejects every ExecuteRedemption because the aggregate stays at 0 while the
        // Step-6 decrement in handle_execute_redemption tries to subtract backing_num.
        group.header.source_fresh_backing_total_num = percolator::V16PodU128::new(
            group
                .header
                .source_fresh_backing_total_num
                .get()
                .checked_add(amount_num)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?,
        );
        source.credit_rate_num =
            expected_source_credit_rate_num(source).map_err(map_v16_error)?;
        source.credit_epoch = source
            .credit_epoch
            .checked_add(1)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        group.header.risk_epoch = percolator::V16PodU64::new(
            group
                .header
                .risk_epoch
                .get()
                .checked_add(1)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?,
        );
        *source_acc = percolator::SourceCreditStateV16Account::from_runtime(&source);
        *bucket_acc = percolator::BackingBucketV16Account::from_runtime(&bucket);
        Ok(())
    }

    fn account<'a>(
        accounts: &'a [AccountInfo<'a>],
        idx: usize,
    ) -> Result<&'a AccountInfo<'a>, ProgramError> {
        accounts.get(idx).ok_or(ProgramError::NotEnoughAccountKeys)
    }


    fn create_pda_account<'a>(
        payer: &AccountInfo<'a>,
        target: &AccountInfo<'a>,
        system_program_ai: &AccountInfo<'a>,
        len: usize,
        owner: &Pubkey,
        signer_seeds: &[&[u8]],
    ) -> ProgramResult {
        let rent_lamports = Rent::get()?.minimum_balance(len);
        let have = target.lamports();

        if have == 0 {
            invoke_signed(
                &system_instruction::create_account(
                    payer.key,
                    target.key,
                    rent_lamports,
                    len as u64,
                    owner,
                ),
                &[payer.clone(), target.clone(), system_program_ai.clone()],
                &[signer_seeds],
            )
        } else {
            if target.owner != &system_program::ID || !target.data_is_empty() {
                return Err(PercolatorError::AlreadyInitialized.into());
            }

            if have < rent_lamports {
                invoke(
                    &system_instruction::transfer(
                        payer.key,
                        target.key,
                        rent_lamports - have,
                    ),
                    &[payer.clone(), target.clone(), system_program_ai.clone()],
                )?;
            }

            invoke_signed(
                &system_instruction::allocate(target.key, len as u64),
                &[target.clone(), system_program_ai.clone()],
                &[signer_seeds],
            )?;

            invoke_signed(
                &system_instruction::assign(target.key, owner),
                &[target.clone(), system_program_ai.clone()],
                &[signer_seeds],
            )
        }
    }

    fn expect_signer(ai: &AccountInfo) -> Result<(), ProgramError> {
        if !ai.is_signer {
            return Err(PercolatorError::ExpectedSigner.into());
        }
        Ok(())
    }

    fn expect_writable(ai: &AccountInfo) -> Result<(), ProgramError> {
        if !ai.is_writable {
            return Err(PercolatorError::ExpectedWritable.into());
        }
        Ok(())
    }

    fn expect_owner(ai: &AccountInfo, owner: &Pubkey) -> Result<(), ProgramError> {
        if ai.owner != owner {
            return Err(ProgramError::IncorrectProgramId);
        }
        Ok(())
    }

    fn expect_live_authority(expected: &[u8; 32], signer: &Pubkey) -> Result<(), ProgramError> {
        if !live_authority_matches(expected, signer) {
            return Err(PercolatorError::Unauthorized.into());
        }
        Ok(())
    }

    fn live_authority_matches(expected: &[u8; 32], signer: &Pubkey) -> bool {
        *expected != [0u8; 32] && *expected == signer.to_bytes()
    }

    fn expect_portfolio_view_owner(
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        owner: &Pubkey,
    ) -> Result<(), ProgramError> {
        if portfolio.header.owner != owner.to_bytes() {
            return Err(PercolatorError::Unauthorized.into());
        }
        Ok(())
    }

    // ════════════════════════════════════════════════════════════════════════
    // E2 — native NFT-holder authorization
    //
    // Under #105 escrow-at-mint a wrapped position's `portfolio.owner` is the NFT
    // program's mint-authority PDA, so the plain `owner == signer` check freezes
    // it (issue #146: undefendable). E2 adds an alternative auth path: the CURRENT
    // HOLDER of the bound NFT may operate the position directly. Control then
    // follows the token automatically on transfer (no per-transfer CPI — dissolves
    // #141/#145), and the holder can margin-defend while wrapped (dissolves #146).
    //
    // Binding storage = Option (b): the wrapper cross-reads the NFT program's
    // PositionNftV16 PDA (no portfolio-struct growth) to learn the bound mint, then
    // checks the signer holds it. The PositionNftV16 byte offsets below are PINNED
    // to ~/v17/percolator-nft/src/state_v16.rs (repr(C), align 1, total 199 bytes,
    // enforced by that crate's `POSITION_NFT_V16_LEN == 199` assert). Any layout
    // change there MUST update these.
    // ════════════════════════════════════════════════════════════════════════

    /// PositionNftV16 field offsets (repr(C), align 1) — pinned to percolator-nft.
    const NFT_PDA_OFF_PORTFOLIO_ACCOUNT: usize = 10; // [10..42]
    const NFT_PDA_OFF_NFT_MINT: usize = 42; // [42..74]
    const NFT_PDA_OFF_MARKET_ID_AT_MINT: usize = 111; // [111..119]
    const NFT_PDA_MIN_LEN: usize = 199;
    /// PositionNft PDA seed (percolator-nft `POSITION_NFT_SEED`).
    const NFT_POSITION_SEED: &[u8] = b"position_nft";

    /// Token-2022 program id. Position NFT mints are Token-2022, so a holder's NFT
    /// token account is owned by THIS program (not classic `spl_token::ID`).
    const TOKEN_2022_PROGRAM_ID: Pubkey =
        solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

    /// Read (mint, owner, amount, initialized) from an SPL OR Token-2022 token
    /// account's base layout (identical first 165 bytes; Token-2022 extensions
    /// follow). The classic-only `unpack_token_account` (requires owner ==
    /// spl_token::ID) cannot read a Token-2022 NFT ATA, so E2 uses this for the
    /// NFT-holder token account.
    fn read_nft_holder_token_account(
        ai: &AccountInfo,
    ) -> Result<([u8; 32], [u8; 32], u64, bool), ProgramError> {
        if ai.owner != &spl_token::ID && ai.owner != &TOKEN_2022_PROGRAM_ID {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        let data = ai.try_borrow_data()?;
        if data.len() < spl_token::state::Account::LEN {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[0..32]);
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&data[32..64]);
        let amount = u64::from_le_bytes(data[64..72].try_into().unwrap());
        // SPL/Token-2022 base layout: AccountState byte at offset 108; 1 == Initialized.
        let initialized = data[108] == 1;
        Ok((mint, owner, amount, initialized))
    }

    /// The three trailing accounts a caller supplies to take the NFT-holder auth
    /// path. Omitted (None) for the normal `owner == signer` path.
    struct NftHolderAccounts<'a, 'info> {
        /// Per-market NftRegistry PDA `["nft_registry", market_group]` (this program).
        registry: &'a AccountInfo<'info>,
        /// The PositionNft PDA `["position_nft", portfolio, market_id_le]` (NFT program).
        nft_account: &'a AccountInfo<'info>,
        /// The signer's SPL token account holding the bound NFT (amount == 1).
        signer_ata: &'a AccountInfo<'info>,
    }

    /// Authorize an owner-gated portfolio mutation by EITHER `owner == signer`
    /// (normal, zero-overhead) OR — for an NFT-escrowed portfolio — proof that the
    /// signer holds the bound NFT. Fund-safety: callers route funds to `signer`
    /// (the holder), never to `portfolio.owner` (the escrow PDA); see handle_withdraw.
    /// View-based wrapper around the scalar core (used by all chokepoint handlers).
    fn authorize_owner_or_nft_holder(
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        portfolio_key: &Pubkey,
        signer: &Pubkey,
        nft: Option<NftHolderAccounts<'_, '_>>,
        program_id: &Pubkey,
    ) -> Result<(), ProgramError> {
        authorize_owner_or_nft_holder_raw(
            &portfolio.header.owner,
            portfolio_key,
            &portfolio.header.provenance_header.market_group_id,
            signer,
            nft,
            program_id,
        )
    }

    /// Scalar core — works before a full engine view exists (e.g. the TradeCpi
    /// preflight, which reads `(owner, market_group)` via read_portfolio_owner_preflight).
    fn authorize_owner_or_nft_holder_raw(
        portfolio_owner: &[u8; 32],
        portfolio_key: &Pubkey,
        market_group: &[u8; 32],
        signer: &Pubkey,
        nft: Option<NftHolderAccounts<'_, '_>>,
        program_id: &Pubkey,
    ) -> Result<(), ProgramError> {
        // ── Normal path: signer IS the portfolio owner. ──
        if *portfolio_owner == signer.to_bytes() {
            return Ok(());
        }

        // ── NFT-holder path: requires the trailing accounts. ──
        let nft = nft.ok_or(PercolatorError::Unauthorized)?;

        // (1) Validate the per-market registry account and read the trusted NFT program.
        let market_group = Pubkey::new_from_array(*market_group);
        let (expected_registry, _) = state::derive_nft_registry(program_id, &market_group);
        expect_key(nft.registry, &expected_registry)?;
        expect_owner(nft.registry, program_id)?;
        let registry = state::read_nft_registry(&nft.registry.try_borrow_data()?)
            .map_err(|_| PercolatorError::NftRegistryNotFound)?;
        let nft_program_id = Pubkey::new_from_array(registry.nft_program_id);

        // After the registry trust-root is validated above, `nft_program_id` is
        // trusted. The remaining checks are gathered as explicit gate values and
        // fed to the PURE decision `nft_holder_auth_decision` (Kani-proven: every
        // gate load-bearing + accept reachable — see tests/v16_kani.rs). I/O here;
        // the AUTHORIZATION VERDICT lives entirely in that pure function.
        let (expected_mint_auth, _) = state::derive_nft_mint_authority(&nft_program_id);

        // (2) PositionNft PDA — must be NFT-program-owned (so its bytes are
        //     trustworthy). Read its bound portfolio + mint + market_id.
        let pda_owner_is_nft_program = nft.nft_account.owner == &nft_program_id;
        let (pda_portfolio_account, bound_mint, market_id) = {
            let data = nft.nft_account.try_borrow_data()?;
            if data.len() < NFT_PDA_MIN_LEN {
                return Err(PercolatorError::Unauthorized.into());
            }
            let mut pa = [0u8; 32];
            pa.copy_from_slice(&data[NFT_PDA_OFF_PORTFOLIO_ACCOUNT..NFT_PDA_OFF_PORTFOLIO_ACCOUNT + 32]);
            let mut mint = [0u8; 32];
            mint.copy_from_slice(&data[NFT_PDA_OFF_NFT_MINT..NFT_PDA_OFF_NFT_MINT + 32]);
            let mut mid = [0u8; 8];
            mid.copy_from_slice(&data[NFT_PDA_OFF_MARKET_ID_AT_MINT..NFT_PDA_OFF_MARKET_ID_AT_MINT + 8]);
            (pa, mint, u64::from_le_bytes(mid))
        };
        // (3) Canonical PDA for that market_id under the trusted NFT program.
        let (expected_nft_pda, _) = Pubkey::find_program_address(
            &[NFT_POSITION_SEED, portfolio_key.as_ref(), &market_id.to_le_bytes()],
            &nft_program_id,
        );
        let pda_is_canonical = nft.nft_account.key == &expected_nft_pda;

        // (4) The signer's token account for the bound NFT. The Position NFT mint
        //     is a Token-2022 mint, so its ATA is owned by the TOKEN-2022 program —
        //     the classic-only `unpack_token_account` (requires owner == spl_token::ID)
        //     would reject EVERY real holder. Read the base (mint, owner, amount,
        //     init) accepting either SPL or Token-2022 (both share the 165-byte base
        //     layout; Token-2022 extensions follow).
        let (ata_mint, ata_owner, ata_amount, ata_initialized) =
            read_nft_holder_token_account(nft.signer_ata)?;

        // ── Verdict (pure, Kani-proven) ──
        let authorized = nft_holder_auth_decision(
            *portfolio_owner,
            expected_mint_auth.to_bytes(),
            pda_owner_is_nft_program,
            pda_portfolio_account,
            portfolio_key.to_bytes(),
            pda_is_canonical,
            bound_mint,
            ata_mint,
            signer.to_bytes(),
            ata_owner,
            ata_amount,
            ata_initialized,
        );
        if authorized {
            Ok(())
        } else {
            Err(PercolatorError::Unauthorized.into())
        }
    }

    /// PURE NFT-holder authorization verdict (no I/O) — the load-bearing fund-safety
    /// gate, isolated so Kani can prove it exhaustively. Returns true iff the signer
    /// genuinely holds the bound NFT of a portfolio escrowed under this NFT program:
    /// the portfolio is owned by the program's mint-authority PDA; the PositionNft
    /// PDA is NFT-program-owned, binds THIS portfolio, and is its canonical address;
    /// and the signer's token account holds exactly one unit of the bound mint.
    /// EVERY conjunct is proven load-bearing (flipping any one → false) and the
    /// accept path is proven reachable in tests/v16_kani.rs (anti-vacuity).
    pub fn nft_holder_auth_decision(
        portfolio_owner: [u8; 32],
        expected_mint_auth: [u8; 32],
        pda_owner_is_nft_program: bool,
        pda_portfolio_account: [u8; 32],
        portfolio_key: [u8; 32],
        pda_is_canonical: bool,
        bound_mint: [u8; 32],
        ata_mint: [u8; 32],
        signer: [u8; 32],
        ata_owner: [u8; 32],
        ata_amount: u64,
        ata_initialized: bool,
    ) -> bool {
        portfolio_owner == expected_mint_auth      // escrowed under THIS NFT program
            && pda_owner_is_nft_program            // PositionNft PDA is genuine
            && pda_portfolio_account == portfolio_key // it binds THIS portfolio
            && pda_is_canonical                    // and is the canonical PDA
            && ata_mint == bound_mint              // token is the BOUND mint
            && ata_owner == signer                 // signer owns the token account
            && ata_amount == 1                     // holds exactly one
            && ata_initialized
    }

    /// Build the optional NFT-holder auth accounts from a handler's account slice,
    /// expecting the trio `[base]=registry, [base+1]=PositionNft PDA, [base+2]=signer
    /// NFT ATA`. Returns None (normal owner==signer path) when fewer than 3 trailing
    /// accounts are present, so non-escrowed callers pass exactly their usual accounts.
    fn optional_nft_holder_accounts<'a, 'info>(
        accounts: &'a [AccountInfo<'info>],
        base: usize,
    ) -> Option<NftHolderAccounts<'a, 'info>> {
        match (
            accounts.get(base),
            accounts.get(base + 1),
            accounts.get(base + 2),
        ) {
            (Some(registry), Some(nft_account), Some(signer_ata)) => Some(NftHolderAccounts {
                registry,
                nft_account,
                signer_ata,
            }),
            _ => None,
        }
    }

    fn expect_portfolio_view_account_key(
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        key: &Pubkey,
    ) -> Result<(), ProgramError> {
        let header = portfolio
            .header
            .provenance_header
            .try_to_runtime()
            .map_err(map_v16_error)?;
        if header.portfolio_account_id != key.to_bytes() {
            return Err(PercolatorError::EngineProvenanceMismatch.into());
        }
        Ok(())
    }

    fn portfolio_has_active_asset_view(
        group: &state::MarketViewMutV16<'_>,
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        asset_index: usize,
    ) -> Result<bool, ProgramError> {
        if asset_index >= group.markets.len() {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let asset = group.markets[asset_index].engine.asset;
        if asset.stored_pos_count_long.get() == 0 && asset.stored_pos_count_short.get() == 0 {
            return Ok(false);
        }
        let market_id = asset.market_id.get();
        let mut slot = 0usize;
        while slot < percolator::V16_MAX_PORTFOLIO_ASSETS_N {
            let leg = portfolio.header.legs[slot]
                .try_to_runtime()
                .map_err(map_v16_error)?;
            if leg.active && leg.asset_index as usize == asset_index && leg.market_id == market_id {
                return Ok(true);
            }
            slot += 1;
        }
        Ok(false)
    }

    fn ensure_trade_portfolio_current_for_requests_view(
        group: &state::MarketViewMutV16<'_>,
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        requests: &[TradeRequestV16],
    ) -> ProgramResult {
        let active_bitmap = portfolio
            .header
            .active_bitmap
            .map(percolator::V16PodU64::get);
        let mut touches_existing_asset = false;
        for request in requests {
            if portfolio_has_active_asset_view(group, portfolio, request.asset_index)? {
                touches_existing_asset = true;
                break;
            }
        }
        if !touches_existing_asset {
            return Ok(());
        }
        let cert = portfolio
            .header
            .health_cert
            .try_to_runtime()
            .map_err(map_v16_error)?;
        if percolator::active_bitmap_is_empty(cert.active_bitmap_at_cert)
            || (cert.certified_initial_req == 0
                && cert.certified_maintenance_req == 0
                && cert.certified_worst_case_loss == 0)
        {
            return Ok(());
        }
        // Avoid the pathological 2N stale-leg settlement cliff. Smaller stale
        // portfolios remain engine-handled so first-open and normal UX are not
        // blocked by conservative wrapper currentness heuristics.
        if percolator::active_bitmap_count_ones(cert.active_bitmap_at_cert) < 8 {
            return Ok(());
        }
        if portfolio.header.b_stale_state != 0 {
            return Err(PercolatorError::EngineBStale.into());
        }
        if portfolio.header.stale_state != 0 {
            return Err(PercolatorError::EngineStale.into());
        }
        if !cert.valid
            || cert.cert_oracle_epoch != group.header.oracle_epoch.get()
            || cert.cert_funding_epoch != group.header.funding_epoch.get()
            || cert.cert_risk_epoch != group.header.risk_epoch.get()
            || cert.cert_asset_set_epoch != group.header.asset_set_epoch.get()
            || cert.active_bitmap_at_cert != active_bitmap
        {
            return Err(PercolatorError::EngineStale.into());
        }
        Ok(())
    }

    // FIX W2 (upstream #147 + #160): a CPI trade route (TradeCpi/BatchTradeCpi) previously
    // invoked the untrusted external matcher with no per-asset lifecycle check at all. The
    // engine's own `require_asset_risk_change_allowed` gate (v16.rs) still rejects a
    // risk-increasing trade on a non-Active asset AFTER the matcher CPI returns, so this is not
    // a fund-safety hole by itself -- but it means any taker can force a CPI into an arbitrary,
    // potentially hostile LP-registered matcher program for a trade that is *already known* to
    // be rejected, burning the matcher's CU budget and handing it live CPI execution surface
    // (writable matcher_ctx, readable market/portfolio-derived oracle price) for no reason.
    // Reject before the matcher ever runs.
    fn signed_position_for_asset_view(
        group: &state::MarketViewMutV16<'_>,
        portfolio: &percolator::PortfolioV16ViewMut<'_>,
        asset_index: usize,
    ) -> Result<i128, ProgramError> {
        if asset_index >= group.markets.len() {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        let market_id = group.markets[asset_index].engine.asset.market_id.get();
        let mut slot = 0usize;
        while slot < percolator::V16_MAX_PORTFOLIO_ASSETS_N {
            let leg = portfolio.header.legs[slot]
                .try_to_runtime()
                .map_err(map_v16_error)?;
            if leg.active && leg.asset_index as usize == asset_index && leg.market_id == market_id {
                return Ok(match leg.side {
                    SideV16::Long => leg.basis_pos_q.unsigned_abs() as i128,
                    SideV16::Short => -(leg.basis_pos_q.unsigned_abs() as i128),
                });
            }
            slot += 1;
        }
        Ok(0)
    }

    fn requested_delta_must_increase_risk(current_q: i128, delta_q: i128) -> bool {
        current_q == 0 || (current_q > 0 && delta_q > 0) || (current_q < 0 && delta_q < 0)
    }

    /// `cpi_requests` is (asset_index, SIGNED requested size_q for account_a; account_b's
    /// requested delta is the negation) for every asset touched by this CPI call.
    fn ensure_cpi_trade_asset_lifecycle_before_matcher(
        group: &state::MarketViewMutV16<'_>,
        account_a: &percolator::PortfolioV16ViewMut<'_>,
        account_b: &percolator::PortfolioV16ViewMut<'_>,
        cpi_requests: &[(u16, i128)],
    ) -> ProgramResult {
        for &(asset_index_u16, size_q) in cpi_requests {
            let asset_index = asset_index_u16 as usize;
            if asset_index >= group.header.config.max_market_slots.get() as usize
                || asset_index >= group.markets.len()
            {
                return Err(PercolatorError::InvalidInstruction.into());
            }
            match group.markets[asset_index].engine.asset.lifecycle {
                ASSET_LIFECYCLE_ACTIVE => {}
                ASSET_LIFECYCLE_DRAIN_ONLY | ASSET_LIFECYCLE_RECOVERY => {
                    let account_a_has_asset =
                        portfolio_has_active_asset_view(group, account_a, asset_index)?;
                    let account_b_has_asset =
                        portfolio_has_active_asset_view(group, account_b, asset_index)?;
                    if !account_a_has_asset && !account_b_has_asset {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                    let account_a_pos =
                        signed_position_for_asset_view(group, account_a, asset_index)?;
                    let account_b_pos =
                        signed_position_for_asset_view(group, account_b, asset_index)?;
                    if requested_delta_must_increase_risk(account_a_pos, size_q)
                        || requested_delta_must_increase_risk(account_b_pos, -size_q)
                    {
                        return Err(PercolatorError::EngineLockActive.into());
                    }
                }
                _ => return Err(PercolatorError::EngineLockActive.into()),
            }
        }
        Ok(())
    }

    /// Account-borrowing wrapper for `ensure_cpi_trade_asset_lifecycle_before_matcher` --
    /// builds the market + both portfolio views, runs the lifecycle gate, then drops every
    /// borrow before returning so the caller is free to CPI into the matcher immediately after.
    fn ensure_cpi_trade_asset_lifecycle_before_matcher_from_accounts(
        market_ai: &AccountInfo<'_>,
        account_a_ai: &AccountInfo<'_>,
        account_b_ai: &AccountInfo<'_>,
        max_market_slots: usize,
        cpi_requests: &[(u16, i128)],
    ) -> ProgramResult {
        ensure_portfolio_storage_for_market_slots(account_a_ai, max_market_slots)?;
        ensure_portfolio_storage_for_market_slots(account_b_ai, max_market_slots)?;
        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (_cfg, group) = state::market_view_mut(&mut market_data)?;
        let mut account_a_data = account_a_ai.try_borrow_mut_data()?;
        let mut account_b_data = account_b_ai.try_borrow_mut_data()?;
        let account_a =
            state::portfolio_view_mut_for_market_slots(&mut account_a_data, max_market_slots)?;
        let account_b =
            state::portfolio_view_mut_for_market_slots(&mut account_b_data, max_market_slots)?;
        ensure_cpi_trade_asset_lifecycle_before_matcher(&group, &account_a, &account_b, cpi_requests)
    }

    fn ensure_trade_portfolios_current_for_requests_view(
        group: &state::MarketViewMutV16<'_>,
        account_a: &percolator::PortfolioV16ViewMut<'_>,
        account_b: &percolator::PortfolioV16ViewMut<'_>,
        requests: &[TradeRequestV16],
    ) -> ProgramResult {
        ensure_trade_portfolio_current_for_requests_view(group, account_a, requests)?;
        ensure_trade_portfolio_current_for_requests_view(group, account_b, requests)
    }


    fn close_portfolio_account_to_market_slab(
        portfolio_ai: &AccountInfo<'_>,
        rent_dest_ai: &AccountInfo<'_>,
    ) -> ProgramResult {
        {
            let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
            for b in portfolio_data.iter_mut() {
                *b = 0;
            }
        }
        #[cfg(target_os = "solana")]
        portfolio_ai.realloc(0, false)?;
        let portfolio_lamports = portfolio_ai.lamports();
        if portfolio_lamports != 0 {
            **portfolio_ai.lamports.borrow_mut() = 0;
            **rent_dest_ai.lamports.borrow_mut() = rent_dest_ai
                .lamports()
                .checked_add(portfolio_lamports)
                .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        }
        Ok(())
    }

    fn ensure_portfolio_storage_for_market_slots(
        portfolio_ai: &AccountInfo,
        max_market_slots: usize,
    ) -> ProgramResult {
        let required = state::portfolio_account_len_for_market_slots(max_market_slots)?;
        if portfolio_ai.data_len() < required {
            portfolio_ai.realloc(required, true)?;
        }
        Ok(())
    }

    fn with_one_portfolio_view<'a, F>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        owner_must_sign: bool,
        f: F,
    ) -> ProgramResult
    where
        for<'m, 'p> F: FnOnce(
            &mut state::MarketViewMutV16<'m>,
            &mut percolator::PortfolioV16ViewMut<'p>,
            &WrapperConfigV16,
        ) -> Result<(), V16Error>,
    {
        let owner = account(accounts, 0)?;
        let market_ai = account(accounts, 1)?;
        let portfolio_ai = account(accounts, 2)?;
        if owner_must_sign {
            expect_signer(owner)?;
        }
        expect_writable(market_ai)?;
        expect_writable(portfolio_ai)?;
        expect_owner(market_ai, program_id)?;
        expect_owner(portfolio_ai, program_id)?;
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_ai.try_borrow_data()?)?;
        ensure_portfolio_storage_for_market_slots(portfolio_ai, max_market_slots)?;
        let mut market_data = market_ai.try_borrow_mut_data()?;
        let (cfg, mut group) = state::market_view_mut(&mut market_data)?;
        let mut portfolio_data = portfolio_ai.try_borrow_mut_data()?;
        let mut portfolio =
            state::portfolio_view_mut_for_market_slots(&mut portfolio_data, max_market_slots)?;
        expect_portfolio_view_account_key(&portfolio, portfolio_ai.key)?;
        if owner_must_sign {
            // E2: owner==signer OR signer holds the bound NFT (escrowed). NFT trio at base 3.
            let nft = optional_nft_holder_accounts(accounts, 3);
            authorize_owner_or_nft_holder(&portfolio, portfolio_ai.key, owner.key, nft, program_id)?;
        }
        f(&mut group, &mut portfolio, &cfg).map_err(map_v16_error)?;
        group.validate_shape().map_err(map_v16_error)?;
        portfolio
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)
    }

    // Sparse: (domain, value) per occupied source-domain slot (<= PORTFOLIO_SOURCE_DOMAIN_CAP).
    type SourceBackingSnapshot = alloc::boxed::Box<[(u32, u128)]>;
    // Sparse accumulator: (domain, provider_fee, insurance_fee) entries, keyed by domain.
    type DomainFeeTotals = Vec<(u32, u128, u128)>;

    fn source_counterparty_backing_snapshot_view(
        account: &percolator::PortfolioV16ViewMut<'_>,
    ) -> Result<SourceBackingSnapshot, ProgramError> {
        let mut out = Vec::new();
        for slot in account.header.source_domains.iter() {
            if slot.is_occupied() {
                out.push((
                    slot.domain.get(),
                    slot.source_lien_counterparty_backing_num.get(),
                ));
            }
        }
        Ok(out.into_boxed_slice())
    }

    fn domain_fee_add(
        fees: &mut DomainFeeTotals,
        domain: u32,
        provider_fee: u128,
        insurance_fee: u128,
    ) -> Result<(), ProgramError> {
        let mut i = 0usize;
        while i < fees.len() {
            if fees[i].0 == domain {
                fees[i].1 = fees[i]
                    .1
                    .checked_add(provider_fee)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                fees[i].2 = fees[i]
                    .2
                    .checked_add(insurance_fee)
                    .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                return Ok(());
            }
            i += 1;
        }
        fees.push((domain, provider_fee, insurance_fee));
        Ok(())
    }

    fn backing_fee_policy_for_domain_view(
        group: &state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        domain: usize,
    ) -> Result<(u16, u16), ProgramError> {
        let asset_index = domain / 2;
        let long_side = domain % 2 == 0;
        let profile = read_oracle_profile_from_view(group, cfg, asset_index)?;
        Ok(if long_side {
            (
                profile.backing_trade_fee_bps_long,
                profile.backing_trade_fee_insurance_share_bps_long,
            )
        } else {
            (
                profile.backing_trade_fee_bps_short,
                profile.backing_trade_fee_insurance_share_bps_short,
            )
        })
    }

    fn collect_backing_domain_fees_for_account_view(
        group: &state::MarketViewMutV16<'_>,
        cfg: &WrapperConfigV16,
        account: &percolator::PortfolioV16ViewMut<'_>,
        before: &[(u32, u128)],
        fees_by_domain: &mut DomainFeeTotals,
    ) -> Result<u128, ProgramError> {
        // Iterate only the OCCUPIED source-domain slots (after-state, <= CAP). For each, compute the
        // counterparty-backing increase vs the before snapshot (looked up by domain) and charge the
        // backing fee. O(active source-domains), independent of N.
        let mut total = 0u128;
        for slot in account.header.source_domains.iter() {
            if !slot.is_occupied() {
                continue;
            }
            let domain = slot.domain.get();
            let after = slot.source_lien_counterparty_backing_num.get();
            let before_val = sparse_domain_value_lookup(before, domain);
            if after > before_val {
                let delta_num = after - before_val;
                let (bps, insurance_share_bps) =
                    backing_fee_policy_for_domain_view(group, cfg, domain as usize)?;
                let split = percolator::backing_domain_fee_split_for_lien_delta_num(
                    delta_num,
                    bps,
                    insurance_share_bps,
                )
                .map_err(map_v16_error)?;
                if split.total_fee != 0 {
                    domain_fee_add(
                        fees_by_domain,
                        domain,
                        split.provider_fee,
                        split.insurance_fee,
                    )?;
                    total = total
                        .checked_add(split.total_fee)
                        .ok_or(PercolatorError::EngineArithmeticOverflow)?;
                }
            }
        }
        Ok(total)
    }

    /// `pub` (not just module-private) so the protocol-fee skim's Kani
    /// obligations (~/v17/PROTOCOL-FEE-DESIGN.md §5.2:
    /// `kani_protocol_skim_conserves_total_fee` /
    /// `kani_protocol_skim_never_exceeds_fee_share_bps`) can prove this exact
    /// function from `tests/v16_kani.rs`, not a re-derivation of it.
    pub fn fee_share_floor(amount: u128, share_bps: u16) -> Result<u128, ProgramError> {
        if amount == 0 || share_bps == 0 {
            return Ok(0);
        }
        amount
            .checked_mul(share_bps as u128)
            .map(|v| v / 10_000)
            .ok_or(PercolatorError::EngineArithmeticOverflow.into())
    }

    /// Maintenance/liquidation cranker reward core (protocol-fee RESERVE
    /// amendment, ~/v17/DECISIONS-LEDGER.md): the amount of a fee charge
    /// diverted to the cranker who triggered it, before any
    /// `additional_reserved` floor is applied by the engine's
    /// `credit_account_from_insurance_not_atomic`. Extracted from the three
    /// call sites (`handle_sync_maintenance_fee`'s two cranker branches,
    /// `handle_permissionless_crank`'s liquidation-cranker branch) so it is
    /// independently Kani-provable
    /// (`kani_protocol_fee_reserve_never_starved_by_cranker_reward`, §5.2).
    pub fn maintenance_cranker_reward(
        charged: u128,
        cranker_fee_share_bps: u16,
    ) -> Result<u128, ProgramError> {
        charged
            .checked_mul(cranker_fee_share_bps as u128)
            .map(|v| v / 10_000)
            .ok_or(PercolatorError::EngineArithmeticOverflow.into())
    }

    /// Pure bound-computation core of `handle_withdraw_protocol_fee` (tag
    /// 83), factored out for Kani provability (no-theft obligation, §5.2:
    /// `kani_protocol_claim_never_exceeds_accrued`). `requested_raw == 0`
    /// means "withdraw all currently-available capacity" (mirrors the
    /// handler's `amount == 0` convention). Returns `(transfer_amount,
    /// next_withdrawn)` on success; `next_withdrawn` is always
    /// `<= accrued` and the invariant `transfer_amount <= accrued -
    /// withdrawn` (the un-withdrawn claim at call time) always holds.
    pub fn protocol_fee_withdraw_amount(
        accrued: u128,
        withdrawn: u128,
        requested_raw: u128,
        engine_available: u128,
        vault: u128,
    ) -> Result<(u128, u128), ProgramError> {
        let claim_capacity = accrued.saturating_sub(withdrawn);
        let requested = if requested_raw == 0 {
            claim_capacity
        } else {
            requested_raw
        };
        if requested == 0 || requested > claim_capacity {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let transfer_amount = requested.min(engine_available).min(vault);
        if transfer_amount == 0 {
            return Err(PercolatorError::EngineLockActive.into());
        }
        let next_withdrawn = withdrawn
            .checked_add(transfer_amount)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok((transfer_amount, next_withdrawn))
    }

    fn charge_account_backing_domain_fees_view(
        group: &mut state::MarketViewMutV16<'_>,
        account: &mut percolator::PortfolioV16ViewMut<'_>,
        fees_by_domain: &[(u32, u128, u128)],
    ) -> Result<(), ProgramError> {
        let mut fee_idx = 0usize;
        while fee_idx < fees_by_domain.len() {
            let (domain, provider_fee, insurance_fee) = fees_by_domain[fee_idx];
            fee_idx += 1;
            if provider_fee == 0 && insurance_fee == 0 {
                continue;
            }
            let d = domain as usize;
            group
                .charge_account_backing_fee_not_atomic(account, d, provider_fee, d, insurance_fee)
                .map_err(map_v16_error)?;
        }
        Ok(())
    }

    fn apply_backing_domain_fees_after_trade_view(
        cfg: &WrapperConfigV16,
        group: &mut state::MarketViewMutV16<'_>,
        account_a: &mut percolator::PortfolioV16ViewMut<'_>,
        before_a: &[(u32, u128)],
        account_b: &mut percolator::PortfolioV16ViewMut<'_>,
        before_b: &[(u32, u128)],
    ) -> Result<u128, ProgramError> {
        let mut fees_a_by_domain: DomainFeeTotals = Vec::new();
        let fee_a = collect_backing_domain_fees_for_account_view(
            group,
            cfg,
            account_a,
            before_a,
            &mut fees_a_by_domain,
        )?;
        let mut fees_b_by_domain: DomainFeeTotals = Vec::new();
        let fee_b = collect_backing_domain_fees_for_account_view(
            group,
            cfg,
            account_b,
            before_b,
            &mut fees_b_by_domain,
        )?;
        if fee_a == 0 && fee_b == 0 {
            return Ok(0);
        }
        charge_account_backing_domain_fees_view(group, account_a, &fees_a_by_domain)?;
        charge_account_backing_domain_fees_view(group, account_b, &fees_b_by_domain)?;
        group.validate_shape().map_err(map_v16_error)?;
        account_a
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)?;
        account_b
            .validate_with_market(&group.as_view())
            .map_err(map_v16_error)?;
        fee_a
            .checked_add(fee_b)
            .ok_or(PercolatorError::EngineArithmeticOverflow.into())
    }

    fn asset_local_has_position_or_loss_state_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
    ) -> bool {
        if asset_index >= group.header.config.max_market_slots.get() as usize
            || asset_index >= group.markets.len()
        {
            return true;
        }
        let asset = &group.markets[asset_index].engine.asset;
        asset.oi_eff_long_q.get() != 0
            || asset.oi_eff_short_q.get() != 0
            || asset.stored_pos_count_long.get() != 0
            || asset.stored_pos_count_short.get() != 0
            || asset.stale_account_count_long.get() != 0
            || asset.stale_account_count_short.get() != 0
            || asset.b_long_num.get() != 0
            || asset.b_short_num.get() != 0
            || asset.b_epoch_start_long_num.get() != 0
            || asset.b_epoch_start_short_num.get() != 0
            || asset.loss_weight_sum_long.get() != 0
            || asset.loss_weight_sum_short.get() != 0
            || asset.social_loss_remainder_long_num.get() != 0
            || asset.social_loss_remainder_short_num.get() != 0
            || asset.social_loss_dust_long_num.get() != 0
            || asset.social_loss_dust_short_num.get() != 0
            || asset.explicit_unallocated_loss_long.get() != 0
            || asset.explicit_unallocated_loss_short.get() != 0
            || asset.mode_long != 0
            || asset.mode_short != 0
    }

    fn trade_notional_floor(size_q: u128, price: u64) -> Result<u128, ProgramError> {
        Ok(size_q
            .checked_mul(price as u128)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?
            / percolator::POS_SCALE)
    }

    fn risk_notional_ceil(size_q: u128, price: u64) -> Result<u128, ProgramError> {
        let num = size_q
            .checked_mul(price as u128)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        Ok(num
            .checked_add(percolator::POS_SCALE - 1)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?
            / percolator::POS_SCALE)
    }

    // Per-asset accrual dt, mirroring the engine's
    // `segment_dt = min(now - asset.slot_last, max_accrual_dt_slots)` in
    // `accrue_asset_to_not_atomic`. The crank price clamp MUST use this, not the
    // group-level dt: `header.slot_last == min(per-asset slot_last)`, so in a
    // multi-asset market a fresher asset has a group dt strictly larger than its
    // own accrual dt. Clamping with the wider group dt lets the wrapper hand the
    // engine a price its per-asset envelope rejects (RecoveryRequired), bricking
    // that asset's crank until the stalest asset is cranked first. Clamping with
    // the per-asset dt makes the wrapper clamp bound exactly match the engine
    // envelope bound for the cranked asset.
    fn asset_segment_dt_view(
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        now_slot: u64,
    ) -> Result<u64, ProgramError> {
        let asset_slot_last = group.markets[asset_index].engine.asset.slot_last.get();
        if now_slot < asset_slot_last {
            return Err(PercolatorError::EngineStale.into());
        }
        Ok(core::cmp::min(
            now_slot - asset_slot_last,
            group.header.config.max_accrual_dt_slots.get(),
        ))
    }

    fn hybrid_trade_fee_bps_view(
        cfg: &WrapperConfigV16,
        profile: &state::AssetOracleProfileV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        size_q_abs: u128,
        exec_price: u64,
        caller_fee_bps: u64,
    ) -> Result<u64, ProgramError> {
        let base = core::cmp::max(caller_fee_bps, cfg.trade_fee_base_bps);
        let max_trading_fee_bps = group.header.config.max_trading_fee_bps.get();
        if base > max_trading_fee_bps {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if !oracle_v16::profile_is_price_managed(profile) {
            return Ok(base);
        }
        if oracle_v16::profile_is_auth_mark(profile) {
            return Ok(base);
        }
        let now_slot = authenticated_market_slot_or_fallback_view(group);
        if oracle_v16::profile_is_hybrid(profile)
            && !oracle_v16::profile_hybrid_soft_stale_matured(profile, now_slot)
        {
            return Ok(base);
        }
        if asset_index >= group.header.config.max_market_slots.get() as usize
            || profile.mark_ewma_e6 == 0
        {
            return Ok(base);
        }
        let asset = group.markets[asset_index].engine.asset;
        let effective_price = asset.effective_price.get();
        let trade_notional = trade_notional_floor(size_q_abs, exec_price)?;
        let clamped_exec = oracle_v16::clamp_toward_engine_dt(
            effective_price,
            exec_price,
            group.header.config.max_price_move_bps_per_slot.get(),
            1,
        );
        let max_side_oi_q = core::cmp::max(asset.oi_eff_long_q.get(), asset.oi_eff_short_q.get());
        let max_side_notional = risk_notional_ceil(max_side_oi_q, effective_price)?;
        let mark_externality_notional = core::cmp::max(max_side_notional, trade_notional)
            .checked_mul(2)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        // Per-asset dt (not group dt): the externality floor must reflect only the
        // traded asset's own staleness, matching the engine accrual envelope and
        // the crank-price clamp. Group dt would over-charge / revert a fresh
        // asset's trade when an unrelated co-asset is stale.
        let segment_dt = core::cmp::max(1, asset_segment_dt_view(group, asset_index, now_slot)?);
        let min_externality_bps = group
            .header
            .config
            .max_price_move_bps_per_slot
            .get()
            .checked_mul(segment_dt)
            .ok_or(PercolatorError::EngineArithmeticOverflow)?;
        let required = policy_v16::dynamic_fee_bps_with_externality_floor(
            base,
            profile.mark_ewma_e6,
            clamped_exec,
            profile.mark_ewma_halflife_slots,
            profile.mark_ewma_last_slot,
            now_slot,
            trade_notional,
            mark_externality_notional,
            profile.mark_min_fee,
            min_externality_bps,
        )
        .ok_or(PercolatorError::EngineInvalidConfig)?;
        let fee = core::cmp::max(base, required);
        if fee > max_trading_fee_bps {
            return Err(PercolatorError::EngineInvalidConfig.into());
        }
        Ok(fee)
    }

    fn hybrid_effective_price_for_crank_view(
        cfg: &WrapperConfigV16,
        profile: &mut state::AssetOracleProfileV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        now_slot: u64,
        now_unix_ts: i64,
        oracle_accounts: &[AccountInfo],
    ) -> Result<u64, ProgramError> {
        if asset_index >= group.header.config.max_market_slots.get() as usize {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        if oracle_v16::profile_is_ewma_mark(profile) || oracle_v16::profile_is_auth_mark(profile) {
            let target = profile.mark_ewma_e6;
            if target == 0 {
                return Err(PercolatorError::OracleInvalid.into());
            }
            let asset = group.markets[asset_index].engine.asset;
            let exposed = asset.oi_eff_long_q.get() != 0 || asset.oi_eff_short_q.get() != 0;
            let price = oracle_v16::effective_price_from_target(
                asset.effective_price.get(),
                target,
                group.header.config.max_price_move_bps_per_slot.get(),
                asset_segment_dt_view(group, asset_index, now_slot)?,
                exposed,
            );
            profile.oracle_target_price_e6 = target;
            return Ok(price);
        }
        if !oracle_v16::profile_is_hybrid(profile) {
            let price = group.markets[asset_index]
                .engine
                .asset
                .effective_price
                .get();
            if price == 0 {
                return Err(PercolatorError::OracleInvalid.into());
            }
            profile.oracle_target_price_e6 = price;
            return Ok(price);
        }
        if cfg.permissionless_resolve_stale_slots != 0
            && now_slot.saturating_sub(profile.last_good_oracle_slot)
                >= cfg.permissionless_resolve_stale_slots
        {
            return Err(PercolatorError::EngineRecoveryRequired.into());
        }
        let count = profile.oracle_leg_count as usize;
        let read = if oracle_accounts.len() >= count {
            oracle_v16::read_external_price_e6_profile(profile, oracle_accounts, now_unix_ts)
        } else {
            Err(ProgramError::NotEnoughAccountKeys)
        };
        let target = match read {
            Ok((price, publish_time, advanced)) => {
                profile.oracle_target_price_e6 = price;
                profile.oracle_target_publish_time = publish_time;
                if advanced {
                    profile.last_good_oracle_slot = now_slot;
                }
                price
            }
            Err(e)
                if e == ProgramError::from(PercolatorError::OracleStale)
                    || e == ProgramError::NotEnoughAccountKeys =>
            {
                if !oracle_v16::profile_hybrid_soft_stale_matured(profile, now_slot) {
                    return Err(e);
                }
                profile.mark_ewma_e6
            }
            Err(e) => return Err(e),
        };
        if target == 0 {
            return Err(PercolatorError::OracleInvalid.into());
        }
        let asset = group.markets[asset_index].engine.asset;
        let exposed = asset.oi_eff_long_q.get() != 0 || asset.oi_eff_short_q.get() != 0;
        let price = oracle_v16::effective_price_from_target(
            asset.effective_price.get(),
            target,
            group.header.config.max_price_move_bps_per_slot.get(),
            asset_segment_dt_view(group, asset_index, now_slot)?,
            exposed,
        );
        profile.oracle_target_price_e6 = target;
        if !oracle_v16::profile_hybrid_soft_stale_matured(profile, now_slot) {
            profile.mark_ewma_e6 = price;
            profile.mark_ewma_last_slot = now_slot;
        }
        Ok(price)
    }

    fn permissionless_funding_rate_e9_view(
        profile: &state::AssetOracleProfileV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        effective_price: u64,
    ) -> Result<i128, ProgramError> {
        if !oracle_v16::profile_is_price_managed(profile) {
            return Ok(0);
        }
        let max_abs_rate = group.header.config.max_abs_funding_e9_per_slot.get();
        if max_abs_rate == 0 {
            return Ok(0);
        }
        if asset_index >= group.header.config.max_market_slots.get() as usize
            || asset_index >= group.markets.len()
        {
            return Err(PercolatorError::InvalidInstruction.into());
        }
        let asset = group.markets[asset_index].engine.asset;
        if profile.mark_ewma_last_slot > asset.slot_last.get() {
            return Ok(0);
        }
        policy_v16::premium_funding_rate_e9(profile.mark_ewma_e6, effective_price, max_abs_rate)
            .ok_or(PercolatorError::EngineArithmeticOverflow.into())
    }

    fn update_hybrid_mark_after_trade_view(
        profile: &mut state::AssetOracleProfileV16,
        group: &state::MarketViewMutV16<'_>,
        asset_index: usize,
        exec_price: u64,
        fee_paid: u128,
    ) -> Result<(), ProgramError> {
        let now_slot = authenticated_market_slot_or_fallback_view(group);
        let ewma_updates_from_trade = oracle_v16::profile_is_ewma_mark(profile)
            || (oracle_v16::profile_is_hybrid(profile)
                && oracle_v16::profile_hybrid_soft_stale_matured(profile, now_slot));
        if !ewma_updates_from_trade
            || asset_index >= group.header.config.max_market_slots.get() as usize
        {
            return Ok(());
        }
        let fee_paid = u64::try_from(fee_paid).unwrap_or(u64::MAX);
        let effective_price = group.markets[asset_index]
            .engine
            .asset
            .effective_price
            .get();
        let clamped_exec = oracle_v16::clamp_toward_engine_dt(
            effective_price,
            exec_price,
            group.header.config.max_price_move_bps_per_slot.get(),
            1,
        );
        let old = profile.mark_ewma_e6;
        let new_mark = policy_v16::ewma_update(
            old,
            clamped_exec,
            profile.mark_ewma_halflife_slots,
            profile.mark_ewma_last_slot,
            now_slot,
            fee_paid,
            profile.mark_min_fee,
        );
        if new_mark > percolator::MAX_ORACLE_PRICE {
            return Err(PercolatorError::OracleInvalid.into());
        }
        if new_mark != 0 && new_mark != old {
            profile.mark_ewma_e6 = new_mark;
            profile.mark_ewma_last_slot = now_slot;
        }
        Ok(())
    }

    fn derive_matcher_delegate(
        program_id: &Pubkey,
        market_key: &Pubkey,
        maker_account: &Pubkey,
        maker_owner: &Pubkey,
        matcher_program: &Pubkey,
        matcher_context: &Pubkey,
    ) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[
                b"matcher",
                market_key.as_ref(),
                maker_account.as_ref(),
                maker_owner.as_ref(),
                matcher_program.as_ref(),
                matcher_context.as_ref(),
            ],
            program_id,
        )
    }

    fn matcher_lp_account_id(delegate: &Pubkey) -> u64 {
        let bytes = delegate.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    }

    fn invoke_matcher<'a>(
        matcher_prog: &AccountInfo<'a>,
        matcher_ctx: &AccountInfo<'a>,
        matcher_delegate: &AccountInfo<'a>,
        tail: &[AccountInfo<'a>],
        req_id: u64,
        asset_index: u16,
        lp_account_id: u64,
        oracle_price_e6: u64,
        req_size: i128,
        seeds: &[&[u8]],
    ) -> ProgramResult {
        let mut data = [0u8; 67];
        data[0] = 0;
        data[1..9].copy_from_slice(&req_id.to_le_bytes());
        data[9..11].copy_from_slice(&(asset_index as u16).to_le_bytes());
        data[11..19].copy_from_slice(&lp_account_id.to_le_bytes());
        data[19..27].copy_from_slice(&oracle_price_e6.to_le_bytes());
        data[27..43].copy_from_slice(&req_size.to_le_bytes());

        let mut metas = Vec::with_capacity(2 + tail.len());
        metas.push(AccountMeta::new_readonly(*matcher_delegate.key, true));
        metas.push(AccountMeta::new(*matcher_ctx.key, false));
        for ai in tail {
            if ai.is_writable {
                metas.push(AccountMeta::new(*ai.key, ai.is_signer));
            } else {
                metas.push(AccountMeta::new_readonly(*ai.key, ai.is_signer));
            }
        }

        let ix = SolInstruction {
            program_id: *matcher_prog.key,
            accounts: metas,
            data: data.to_vec(),
        };
        let mut infos = Vec::with_capacity(3 + tail.len());
        infos.push(matcher_delegate.clone());
        infos.push(matcher_ctx.clone());
        infos.push(matcher_prog.clone());
        for ai in tail {
            infos.push(ai.clone());
        }
        invoke_signed(&ix, &infos, &[seeds])
    }

    fn amount_to_u64(amount: u128) -> Result<u64, ProgramError> {
        u64::try_from(amount).map_err(|_| PercolatorError::InvalidInstruction.into())
    }

    fn derive_vault_authority(program_id: &Pubkey, market_key: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"vault", market_key.as_ref()], program_id)
    }

    /// ProgramData PDA for `program_id` under the upgradeable BPF loader —
    /// standard Solana pattern, new to this codebase (design §2/§3.2).
    fn derive_program_data_address(program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id())
    }

    /// Reads `upgrade_authority_address` out of a `UpgradeableLoaderState::ProgramData`
    /// account's raw bytes without pulling in a bincode dependency for this
    /// no_std program: the loader's on-chain serialization of this variant
    /// is a stable, consensus-critical layout —
    /// `UpgradeableLoaderState::size_of_programdata_metadata() == 45`
    /// (4-byte little-endian enum discriminant, 8-byte `slot`, then a
    /// 1-byte `Option` tag + 32-byte pubkey for `upgrade_authority_address`).
    /// `ProgramData` is variant index 3 (`Uninitialized`=0, `Buffer`=1,
    /// `Program`=2, `ProgramData`=3).
    /// Pure byte-parsing core of `read_program_data_upgrade_authority`,
    /// extracted for Kani provability
    /// (`kani_set_protocol_fee_authority_requires_upgrade_authority`, §5.2 --
    /// SetProtocolFeeAuthority/tag-85 gate). Operates on a raw slice so it
    /// needs no `AccountInfo`/syscalls; the owner check and the
    /// `AccountInfo` borrow remain in the caller.
    pub fn parse_program_data_upgrade_authority_bytes(
        data: &[u8],
    ) -> Result<Option<Pubkey>, ProgramError> {
        if data.len() < 45 {
            return Err(ProgramError::InvalidAccountData);
        }
        let discriminant = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if discriminant != 3 {
            return Err(ProgramError::InvalidAccountData);
        }
        match data[12] {
            0 => Ok(None),
            1 => {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&data[13..45]);
                Ok(Some(Pubkey::new_from_array(key_bytes)))
            }
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    fn read_program_data_upgrade_authority(
        program_data_ai: &AccountInfo,
    ) -> Result<Option<Pubkey>, ProgramError> {
        if program_data_ai.owner != &bpf_loader_upgradeable::id() {
            return Err(ProgramError::InvalidAccountData);
        }
        let data = program_data_ai.try_borrow_data()?;
        parse_program_data_upgrade_authority_bytes(&data)
    }

    /// The SPL Associated Token Account program — used to derive the single CANONICAL vault address.
    const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
        solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

    /// The canonical vault for a market+mint is the Associated Token Account of the vault_authority
    /// PDA for that mint. Pinning the vault to this single deterministic address (rather than
    /// accepting ANY vault_authority-owned token account) prevents liquidity fragmentation: an
    /// attacker can no longer route deposits to a second vault_authority-owned account and strand
    /// honest withdrawals against the canonical vault (finding F-VAULT-FRAG).
    fn canonical_vault_address(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[
                vault_authority.as_ref(),
                spl_token::ID.as_ref(),
                mint.as_ref(),
            ],
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        )
        .0
    }

    fn expect_key(ai: &AccountInfo, expected: &Pubkey) -> Result<(), ProgramError> {
        if ai.key != expected {
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }

    fn verify_mint(mint_ai: &AccountInfo) -> Result<(), ProgramError> {
        if mint_ai.owner != &spl_token::ID {
            return Err(PercolatorError::InvalidMint.into());
        }
        if mint_ai.data_len() != spl_token::state::Mint::LEN {
            return Err(PercolatorError::InvalidMint.into());
        }
        let data = mint_ai.try_borrow_data()?;
        spl_token::state::Mint::unpack(&data)
            .map(|_| ())
            .map_err(|_| PercolatorError::InvalidMint.into())
    }

    /// #447: same checks as `verify_mint`, but RETURNS the unpacked mint so callers
    /// can compare fields (upstream's `unpack_mint`). `verify_mint` discards it with
    /// `.map(|_| ())`, which is why the decimals-parity guard was silently droppable.
    fn unpack_mint(mint_ai: &AccountInfo) -> Result<spl_token::state::Mint, ProgramError> {
        if mint_ai.owner != &spl_token::ID {
            return Err(PercolatorError::InvalidMint.into());
        }
        if mint_ai.data_len() != spl_token::state::Mint::LEN {
            return Err(PercolatorError::InvalidMint.into());
        }
        let data = mint_ai.try_borrow_data()?;
        spl_token::state::Mint::unpack(&data).map_err(|_| PercolatorError::InvalidMint.into())
    }

    fn verify_token_program(token_program: &AccountInfo) -> Result<(), ProgramError> {
        if *token_program.key != spl_token::ID || !token_program.executable {
            return Err(PercolatorError::InvalidTokenProgram.into());
        }
        Ok(())
    }

    fn unpack_token_account(
        token_ai: &AccountInfo,
    ) -> Result<spl_token::state::Account, ProgramError> {
        if token_ai.owner != &spl_token::ID {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        if token_ai.data_len() != spl_token::state::Account::LEN {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        let data = token_ai.try_borrow_data()?;
        spl_token::state::Account::unpack(&data)
            .map_err(|_| PercolatorError::InvalidTokenAccount.into())
    }

    fn verify_user_token_account(
        token_ai: &AccountInfo,
        expected_owner: &Pubkey,
        expected_mint: &Pubkey,
    ) -> Result<(), ProgramError> {
        let token = unpack_token_account(token_ai)?;
        if token.mint != *expected_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        if token.owner != *expected_owner
            || token.state != spl_token::state::AccountState::Initialized
        {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        Ok(())
    }

    fn primary_collateral_mint(cfg: &WrapperConfigV16) -> Pubkey {
        Pubkey::new_from_array(cfg.collateral_mint)
    }

    fn secondary_collateral_mint(cfg: &WrapperConfigV16) -> Result<Pubkey, ProgramError> {
        if cfg.secondary_collateral_mint == [0u8; 32] {
            return Err(PercolatorError::InvalidMint.into());
        }
        Ok(Pubkey::new_from_array(cfg.secondary_collateral_mint))
    }

    fn is_withdrawable_collateral_mint(cfg: &WrapperConfigV16, mint: &Pubkey) -> bool {
        mint.to_bytes() == cfg.collateral_mint
            || (cfg.secondary_collateral_mint != [0u8; 32]
                && mint.to_bytes() == cfg.secondary_collateral_mint)
    }

    fn verify_withdrawable_token_accounts(
        dest_token_ai: &AccountInfo,
        expected_dest_owner: &Pubkey,
        vault_token_ai: &AccountInfo,
        expected_vault_owner: &Pubkey,
        cfg: &WrapperConfigV16,
    ) -> Result<(), ProgramError> {
        let dest = unpack_token_account(dest_token_ai)?;
        let vault = unpack_token_account(vault_token_ai)?;
        if dest.mint != vault.mint || !is_withdrawable_collateral_mint(cfg, &dest.mint) {
            return Err(PercolatorError::InvalidMint.into());
        }
        if dest.owner != *expected_dest_owner
            || dest.state != spl_token::state::AccountState::Initialized
        {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        if vault.owner != *expected_vault_owner
            || vault.state != spl_token::state::AccountState::Initialized
            || vault.delegate.is_some()
            || vault.close_authority.is_some()
            // F-VAULT-FRAG: pin to the single canonical vault address (the ATA of the vault_authority
            // for this mint). Without this, ANY vault_authority-owned account is accepted, enabling
            // liquidity fragmentation that strands honest withdrawals.
            || *vault_token_ai.key != canonical_vault_address(expected_vault_owner, &vault.mint)
        {
            return Err(PercolatorError::InvalidVaultAccount.into());
        }
        Ok(())
    }

    // W5 (upstream b7b6688e / #154): terminal payout paths that are PERMISSIONLESS
    // (CloseResolved, ClaimResolvedPayoutTopup -- any caller can trigger the payout,
    // not just the portfolio owner) must additionally reject a `dest_token` that has
    // an active delegate or close_authority. verify_withdrawable_token_accounts above
    // only checks dest.mint/owner/state; a pre-poisoned destination (delegate/close_authority
    // set by an attacker on an account the victim otherwise owns) would let the delegate
    // sweep the payout the instant it lands, with no signature from the victim required
    // to trigger the transfer. Signer-gated withdraw paths (Withdraw, WithdrawInsurance,
    // WithdrawInsuranceAsset, WithdrawBackingBucket[Earnings], WithdrawProtocolFee) are NOT
    // in scope: there the signer picks their own dest_token, so a poisoned account is
    // self-inflicted, not attacker-injectable.
    fn verify_permissionless_payout_dest_token_account(
        dest_token_ai: &AccountInfo,
    ) -> Result<(), ProgramError> {
        let dest = unpack_token_account(dest_token_ai)?;
        if dest.delegate.is_some() || dest.close_authority.is_some() {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        Ok(())
    }

    fn verify_vault_token_account(
        token_ai: &AccountInfo,
        expected_owner: &Pubkey,
        expected_mint: &Pubkey,
    ) -> Result<(), ProgramError> {
        let token = unpack_token_account(token_ai)?;
        if token.mint != *expected_mint {
            return Err(PercolatorError::InvalidMint.into());
        }
        if token.owner != *expected_owner
            || token.state != spl_token::state::AccountState::Initialized
            || token.delegate.is_some()
            || token.close_authority.is_some()
            // F-VAULT-FRAG: pin to the single canonical vault address (ATA of vault_authority+mint).
            || *token_ai.key != canonical_vault_address(expected_owner, expected_mint)
        {
            return Err(PercolatorError::InvalidVaultAccount.into());
        }
        Ok(())
    }

    fn require_token_balance(token_ai: &AccountInfo, amount: u64) -> Result<(), ProgramError> {
        let token = unpack_token_account(token_ai)?;
        if token.amount < amount {
            return Err(PercolatorError::InvalidTokenAccount.into());
        }
        Ok(())
    }

    fn transfer_tokens<'a>(
        token_program: &AccountInfo<'a>,
        source: &AccountInfo<'a>,
        dest: &AccountInfo<'a>,
        authority: &AccountInfo<'a>,
        amount: u64,
    ) -> Result<(), ProgramError> {
        if amount == 0 {
            return Ok(());
        }
        let ix = spl_token::instruction::transfer(
            token_program.key,
            source.key,
            dest.key,
            authority.key,
            &[],
            amount,
        )?;
        invoke(
            &ix,
            &[
                source.clone(),
                dest.clone(),
                authority.clone(),
                token_program.clone(),
            ],
        )
    }

    fn transfer_tokens_signed<'a>(
        token_program: &AccountInfo<'a>,
        source: &AccountInfo<'a>,
        dest: &AccountInfo<'a>,
        authority: &AccountInfo<'a>,
        amount: u64,
        signer_seeds: &[&[&[u8]]],
    ) -> Result<(), ProgramError> {
        if amount == 0 {
            return Ok(());
        }
        let ix = spl_token::instruction::transfer(
            token_program.key,
            source.key,
            dest.key,
            authority.key,
            &[],
            amount,
        )?;
        invoke_signed(
            &ix,
            &[
                source.clone(),
                dest.clone(),
                authority.clone(),
                token_program.clone(),
            ],
            signer_seeds,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloc::vec;
        use percolator::HealthCertV16;

        #[test]
        fn wrapper_config_len_matches_struct_size() {
            assert_eq!(
                core::mem::size_of::<state::WrapperConfigV16>(),
                state::wrapper_config_len_for_test(),
                "WRAPPER_CONFIG_LEN must equal size_of::<WrapperConfigV16>() for the zero-copy layout",
            );
        }

        fn test_wrapper_config(price: u64) -> state::WrapperConfigV16 {
            let mut cfg = state::WrapperConfigV16::default();
            cfg.marketauth = [1u8; 32];
            cfg.collateral_mint = [2u8; 32];
            cfg.oracle_mode = constants::ORACLE_MODE_MANUAL;
            cfg.last_good_oracle_slot = 0;
            cfg.mark_ewma_e6 = price;
            cfg.mark_ewma_halflife_slots = constants::DEFAULT_MARK_EWMA_HALFLIFE_SLOTS;
            cfg.oracle_target_price_e6 = price;
            cfg
        }

        fn test_engine_config() -> V16Config {
            let mut cfg = V16Config::public_user_fund(1, 0, 10);
            cfg.min_nonzero_mm_req = 1;
            cfg.min_nonzero_im_req = 2;
            cfg.maintenance_margin_bps = 10_000;
            cfg.initial_margin_bps = 10_000;
            cfg.max_trading_fee_bps = 10_000;
            cfg.max_price_move_bps_per_slot = 10_000;
            cfg.max_accrual_dt_slots = 1;
            cfg.min_funding_lifetime_slots = 1;
            cfg
        }

        #[test]
        fn premium_funding_rate_e9_clamps_and_preserves_sign() {
            assert_eq!(
                policy_v16::premium_funding_rate_e9(150, 100, 1_000),
                Some(1_000)
            );
            assert_eq!(
                policy_v16::premium_funding_rate_e9(100, 150, 1_000),
                Some(-1_000)
            );
            assert_eq!(
                policy_v16::premium_funding_rate_e9(101, 100, 20_000_000),
                Some(10_000_000)
            );
            assert_eq!(
                policy_v16::premium_funding_rate_e9(100, 100, 1_000),
                Some(0)
            );
            assert_eq!(policy_v16::premium_funding_rate_e9(150, 100, 0), Some(0));
        }

        // ── RETIRED: `fee_split_floor_ok` has no live call sites. ───────────
        //
        // These tests cover code no instruction can reach. They are NOT
        // evidence that the fee-split floors are enforced on-chain; that is
        // `validate_fee_split` (tag 86), covered by the `tag86_*` tests in
        // `tests/v16_fee_split.rs`. Kept only because the function is kept.
        //
        // `#[allow(deprecated)]` is scoped to each of these tests rather than
        // to the module, so the `#[deprecated]` attribute still fires loudly if
        // anyone wires `fee_split_floor_ok` back into a live path.
        //
        // Historical description: on-chain enforcement of the launch wizard's
        // (feeSplit.ts) creator<=45%/LP>=40%/insurance>=15% floors, as a share
        // of the RETIRED two-rate `T = trade_fee_base_bps + backing_fee_bps`.

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_accepts_wizard_default_20_60_20() {
            // T=20bps, creatorPct=20/lpPct=60/insurancePct=20 ->
            // trade_fee_base_bps=round(20*0.20)=4, backing_fee_bps=16,
            // insurance_share_bps=round(20/80*10000)=2500. Passes with wide
            // margin, no tolerance needed.
            assert!(policy_v16::fee_split_floor_ok(4, 16, 2_500));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_rejects_insurance_below_floor() {
            // T=1000bps, tfb=100 (10% creator, well within the 45% cap),
            // bf=900, isb=1000 -> insurance% = 0.9 * 10% = 9% < 15%.
            assert!(!policy_v16::fee_split_floor_ok(100, 900, 1_000));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_rejects_lp_below_floor() {
            // T=1000bps, tfb=100 (10% creator), bf=900, isb=8000 -> LP share
            // is only 2000bps of the backing fee, so LP% = 0.9 * 20% = 18% < 40%.
            assert!(!policy_v16::fee_split_floor_ok(100, 900, 8_000));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_rejects_creator_above_cap() {
            // T=1000bps, tfb=600 -> creator% = 60% > 45%, regardless of the
            // backing-fee split (isb=5000 is otherwise a perfectly valid 50/50
            // insurance/LP split of the backing fee).
            assert!(!policy_v16::fee_split_floor_ok(600, 400, 5_000));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_accepts_zero_creator_share() {
            // tfb=0 (all-to-backing): creator%=0 (<=45% trivially satisfied),
            // bf=1000, isb=2000 -> insurance%=20% (>=15%), LP%=80% (>=40%).
            assert!(policy_v16::fee_split_floor_ok(0, 1_000, 2_000));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_skips_check_when_backing_fee_is_zero() {
            // backing_fee_bps==0 means the three-way split isn't configured
            // yet (e.g. right after InitMarket) -- the floor check is skipped
            // entirely regardless of trade_fee_base_bps/insurance_share_bps.
            // Any pre-existing `insurance_share_bps==0` requirement for this
            // state is a SEPARATE, already-enforced check
            // (`backing_trade_fee_policy_shape_ok`, exercised below) that
            // this function does not duplicate and does not change.
            assert!(policy_v16::fee_split_floor_ok(0, 0, 0));
            assert!(policy_v16::fee_split_floor_ok(10_000, 0, 9_999));
            // The pre-existing shape check (unaffected by this change) still
            // rejects a nonzero insurance share paired with a zero fee.
            assert!(!state::backing_trade_fee_policy_shape_ok(0, 1));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_accepts_wizard_boundary_point_with_rounding() {
            // The tightest realistic edge case: the wizard's own
            // *simultaneous* boundary selection (creatorPct=45, lpPct=40,
            // insurancePct=15 -- all three floors at once) at a low total fee
            // T=10bps. Ideal (unrounded) trade_fee_base_bps = 10*0.45 = 4.5,
            // which Math.round()'s round-half-up rounds to 5 -- the exact 0.5
            // worst case that motivated FEE_SPLIT_CREATOR_TOLERANCE.
            // backing_fee_bps = 10-5 = 5. insurance_share_bps =
            // round(15/55*10000) = round(2727.27) = 2727. The resulting
            // ACTUAL on-chain split is 50% creator / 36.365% LP / 13.635%
            // insurance -- all three floors technically violated by the
            // rounding -- yet this is exactly what the wizard produced for a
            // legitimate boundary input, so it must be accepted.
            assert!(policy_v16::fee_split_floor_ok(5, 5, 2_727));
        }

        #[test]
        #[allow(deprecated)]
        fn fee_split_floor_still_rejects_a_genuinely_bad_split_at_the_same_scale() {
            // Non-vacuity companion to the boundary-point test above: at the
            // same small T=10bps scale, a split that is genuinely (not just
            // rounding-noise) off the floors is still rejected -- confirms
            // the tolerance doesn't degenerate into "always accept" at small T.
            // tfb=9 (90% creator, nowhere near the 45% cap even accounting
            // for the 50-unit tolerance: 900 > 450+50=500).
            assert!(!policy_v16::fee_split_floor_ok(9, 1, 5_000));
        }

        #[test]
        fn backing_domain_fee_split_routes_to_insurance_and_provider_earnings() {
            let mut cfg = test_wrapper_config(100);
            cfg.backing_trade_fee_bps_short = 10;
            cfg.backing_trade_fee_insurance_share_bps_short = 2_500;
            cfg.backing_trade_fee_policy_count = 1;

            let mut market_data = vec![0u8; state::market_account_len_for_capacity(1).unwrap()];
            state::init_market_account_zero_copy(
                &mut market_data,
                &cfg,
                test_engine_config(),
                [9u8; 32],
                100,
                0,
            )
            .unwrap();
            let portfolio_len = state::portfolio_account_len_for_market_slots(1).unwrap();
            let mut account_a_data = vec![0u8; portfolio_len];
            let mut account_b_data = vec![0u8; portfolio_len];
            state::init_portfolio_account_zero_copy(
                &mut account_a_data,
                [9u8; 32],
                [10u8; 32],
                [11u8; 32],
                0,
                1,
            )
            .unwrap();
            state::init_portfolio_account_zero_copy(
                &mut account_b_data,
                [9u8; 32],
                [12u8; 32],
                [13u8; 32],
                0,
                1,
            )
            .unwrap();

            {
                let (cfg_pre, mut group) = state::read_market(&market_data).unwrap();
                let mut account_a = state::read_portfolio(&account_a_data).unwrap();
                let mut account_b = state::read_portfolio(&account_b_data).unwrap();

                account_a.capital = account_a.capital.checked_add(50_000).unwrap();
                account_b.capital = account_b.capital.checked_add(50_000).unwrap();
                group.c_tot = group.c_tot.checked_add(100_000).unwrap();
                group.vault = group.vault.checked_add(100_000).unwrap();

                group.vault += 20_000;
                group.source_backing_buckets[1] = percolator::BackingBucketV16 {
                    market_id: group.assets[0].market_id,
                    fresh_unliened_backing_num: 20_000 * BOUND_SCALE,
                    expiry_slot: 10,
                    status: percolator::BackingBucketStatusV16::Fresh,
                    ..percolator::BackingBucketV16::EMPTY
                };
                group.source_credit[1].fresh_reserved_backing_num = 20_000 * BOUND_SCALE;
                group.source_credit[1].credit_rate_num = percolator::CREDIT_RATE_SCALE;
                group.source_credit[1].credit_epoch =
                    group.source_credit[1].credit_epoch.checked_add(1).unwrap();
                group.risk_epoch = group.risk_epoch.checked_add(1).unwrap();

                group
                    .add_account_source_positive_pnl_not_atomic(&mut account_a, 1, 20_000)
                    .unwrap();

                let locked_atoms = 10_000u128;
                let locked_num = locked_atoms * BOUND_SCALE;
                group.source_backing_buckets[1].fresh_unliened_backing_num = group
                    .source_backing_buckets[1]
                    .fresh_unliened_backing_num
                    .checked_sub(locked_num)
                    .unwrap();
                group.source_backing_buckets[1].valid_liened_backing_num = group
                    .source_backing_buckets[1]
                    .valid_liened_backing_num
                    .checked_add(locked_num)
                    .unwrap();
                group.source_credit[1].valid_liened_backing_num = group.source_credit[1]
                    .valid_liened_backing_num
                    .checked_add(locked_num)
                    .unwrap();
                group.source_credit[1].credit_rate_num = group.source_credit[1]
                    .fresh_reserved_backing_num
                    .checked_sub(group.source_credit[1].valid_liened_backing_num)
                    .unwrap()
                    .checked_mul(percolator::CREDIT_RATE_SCALE)
                    .unwrap()
                    .checked_div(group.source_credit[1].positive_claim_bound_num)
                    .unwrap();
                group.source_credit[1].credit_epoch =
                    group.source_credit[1].credit_epoch.checked_add(1).unwrap();
                group.risk_epoch = group.risk_epoch.checked_add(1).unwrap();

                account_a.source_claim_liened_num[1] = locked_num;
                account_a.source_claim_counterparty_liened_num[1] = locked_num;
                account_a.source_lien_effective_reserved[1] = locked_atoms;
                account_a.source_lien_counterparty_backing_num[1] = locked_num;
                account_a.source_lien_fee_last_slot[1] = group.current_slot;
                account_a.health_cert = HealthCertV16 {
                    certified_equity: 70_000,
                    certified_initial_req: 0,
                    certified_maintenance_req: 0,
                    certified_liq_deficit: 0,
                    certified_worst_case_loss: 0,
                    cert_oracle_epoch: group.oracle_epoch,
                    cert_funding_epoch: group.funding_epoch,
                    cert_risk_epoch: group.risk_epoch,
                    cert_asset_set_epoch: group.asset_set_epoch,
                    active_bitmap_at_cert: account_a.active_bitmap,
                    valid: true,
                };
                account_b.health_cert = HealthCertV16 {
                    certified_equity: 50_000,
                    certified_initial_req: 0,
                    certified_maintenance_req: 0,
                    certified_liq_deficit: 0,
                    certified_worst_case_loss: 0,
                    cert_oracle_epoch: group.oracle_epoch,
                    cert_funding_epoch: group.funding_epoch,
                    cert_risk_epoch: group.risk_epoch,
                    cert_asset_set_epoch: group.asset_set_epoch,
                    active_bitmap_at_cert: account_b.active_bitmap,
                    valid: true,
                };
                state::write_market(&mut market_data, &cfg_pre, &group).unwrap();
                state::write_portfolio(&mut account_a_data, &account_a).unwrap();
                state::write_portfolio(&mut account_b_data, &account_b).unwrap();
            }

            // Sparse pre-trade per-domain backing snapshots: empty == all domains zero.
            let before_a: &[(u32, u128)] = &[];
            let before_b: &[(u32, u128)] = &[];
            {
                let (cfg_view, mut group) = state::market_view_mut(&mut market_data).unwrap();
                let mut account_a =
                    state::portfolio_view_mut_for_market_slots(&mut account_a_data, 1).unwrap();
                let mut account_b =
                    state::portfolio_view_mut_for_market_slots(&mut account_b_data, 1).unwrap();
                let charged = apply_backing_domain_fees_after_trade_view(
                    &cfg_view,
                    &mut group,
                    &mut account_a,
                    before_a,
                    &mut account_b,
                    before_b,
                )
                .unwrap();
                assert_eq!(charged, 10);
            }

            let (_, group) = state::read_market(&market_data).unwrap();
            let account_a = state::read_portfolio(&account_a_data).unwrap();
            assert_eq!(group.insurance, 2);
            assert_eq!(group.source_backing_buckets[1].utilization_fee_earnings, 8);
            assert_eq!(account_a.capital, 49_990);
            assert_eq!(group.c_tot, 99_990);
            assert_eq!(
                group.source_backing_buckets[1].fresh_unliened_backing_num,
                10_000 * BOUND_SCALE,
                "provider fee must not be capitalized back into fresh backing principal"
            );
            assert_eq!(
                group.source_backing_buckets[1].valid_liened_backing_num,
                10_000 * BOUND_SCALE
            );
        }

        #[test]
        fn backing_domain_fee_policy_rejects_share_without_fee() {
            assert!(state::backing_trade_fee_policy_shape_ok(1, 10_000));
            assert!(state::backing_trade_fee_policy_shape_ok(10_000, 0));
            assert!(!state::backing_trade_fee_policy_shape_ok(0, 1));
            assert!(!state::backing_trade_fee_policy_shape_ok(10_001, 0));
            assert!(!state::backing_trade_fee_policy_shape_ok(1, 10_001));
        }

        /// Sweep NET-NEW: PercolatorError fork ordinals 30-50 must not change.
        ///
        /// These ordinals are part of the IDL wire format and are consumed by the
        /// keeper, indexer, and SDK error decoders. Any shift in ordinal = a
        /// BREAKING CHANGE. This test acts as an immutable CI gate: if you rename
        /// or reorder fork error variants the test fails loudly.
        ///
        /// Ordinals 0-29 are pinned by
        /// `upstream_percolator_error_ordinals_are_stable` directly below.
        ///
        /// That claim used to read "tested implicitly by the existing
        /// v16_baseline_smoke tests". It was FALSE: `tests/v16_baseline_smoke.rs`
        /// contains zero `PercolatorError` references and zero `Custom(`
        /// references, so it pinned nothing. `Unauthorized` (8) and
        /// `InvalidInstruction` (9) — two of the most widely decoded codes on
        /// the wire — were protected by nothing at all.
        #[test]
        fn fork_percolator_error_ordinals_are_stable() {
            use crate::error::PercolatorError;
            use solana_program::program_error::ProgramError;

            fn custom_code(e: PercolatorError) -> u32 {
                match ProgramError::from(e) {
                    ProgramError::Custom(n) => n,
                    _ => panic!("not a Custom error"),
                }
            }

            // LP vault errors — ordinals 30-41 (matching enum order in error module).
            assert_eq!(custom_code(PercolatorError::LpVaultAlreadyExists),         30);
            assert_eq!(custom_code(PercolatorError::LpVaultNotFound),              31);
            assert_eq!(custom_code(PercolatorError::LpVaultPaused),                32);
            assert_eq!(custom_code(PercolatorError::LpVaultSharesOutstanding),     33);
            assert_eq!(custom_code(PercolatorError::LpVaultZeroAmount),            34);
            assert_eq!(custom_code(PercolatorError::LpVaultInsufficientShares),    35);
            assert_eq!(custom_code(PercolatorError::LpVaultCooldownActive),        36);
            assert_eq!(custom_code(PercolatorError::LpVaultOiReservationViolated), 37);
            assert_eq!(custom_code(PercolatorError::LpVaultNoFeesToCrank),         38);
            assert_eq!(custom_code(PercolatorError::LpVaultSupplyMismatch),        39);
            assert_eq!(custom_code(PercolatorError::LpVaultAuthorityMismatch),     40);
            assert_eq!(custom_code(PercolatorError::LpVaultZeroSharesMinted),      41);

            // NFT B-3 errors — ordinals 42-46 (matching enum order in error module).
            assert_eq!(custom_code(PercolatorError::NftRegistryNotFound),          42);
            assert_eq!(custom_code(PercolatorError::NftPortfolioNotTransferable),  43);
            assert_eq!(custom_code(PercolatorError::NftTransferSelfOrZero),        44);
            assert_eq!(custom_code(PercolatorError::NftInvalidMintAuthority),      45);
            assert_eq!(custom_code(PercolatorError::NftPortfolioProvenance),       46);
            assert_eq!(custom_code(PercolatorError::InsuranceWithdrawCooldownActive),  47);
            assert_eq!(custom_code(PercolatorError::InsuranceWithdrawCeilingExceeded), 48);
            // FIX-2: distinct initial-margin error — ordinal 49.
            assert_eq!(custom_code(PercolatorError::EngineInsufficientInitialMargin),  49);
            // BUG-2 / N7: LP vault genesis dead-share floor — ordinal 50.
            assert_eq!(custom_code(PercolatorError::LpVaultDepositBelowMinimumLiquidity), 50);
        }

        /// Ordinals 0-29 — the UPSTREAM (toly) variants.
        ///
        /// FINDING 7 (branch review). These were pinned by NOTHING. 30-50 are
        /// pinned above and 51-60 in `tests/v16_fee_split.rs`, but the block
        /// underneath both — including `Unauthorized` (8) and
        /// `InvalidInstruction` (9), the two most widely decoded codes in the
        /// keeper, indexer and SDK — had no assertion anywhere. The comment
        /// above claimed `v16_baseline_smoke` covered them; that file has zero
        /// `PercolatorError` references.
        ///
        /// This enum has NO explicit discriminants, so declaration order IS the
        /// wire ABI: inserting a variant anywhere in this run silently shifts
        /// every code below it and every downstream decoder starts
        /// misattributing errors, with nothing failing to build. That is the
        /// failure this pins.
        ///
        /// Asserting only — no variant is renumbered or reordered here. To add
        /// an error, APPEND it at the tail of the enum and extend the last
        /// block; never insert.
        #[test]
        fn upstream_percolator_error_ordinals_are_stable() {
            use crate::error::PercolatorError;
            use solana_program::program_error::ProgramError;

            fn custom_code(e: PercolatorError) -> u32 {
                match ProgramError::from(e) {
                    ProgramError::Custom(n) => n,
                    _ => panic!("not a Custom error"),
                }
            }

            // Account//framing errors — 0-13.
            assert_eq!(custom_code(PercolatorError::InvalidMagic),              0);
            assert_eq!(custom_code(PercolatorError::InvalidVersion),            1);
            assert_eq!(custom_code(PercolatorError::AlreadyInitialized),        2);
            assert_eq!(custom_code(PercolatorError::NotInitialized),            3);
            assert_eq!(custom_code(PercolatorError::InvalidAccountKind),        4);
            assert_eq!(custom_code(PercolatorError::InvalidAccountLen),         5);
            assert_eq!(custom_code(PercolatorError::ExpectedSigner),            6);
            assert_eq!(custom_code(PercolatorError::ExpectedWritable),          7);
            // The two the review called out as unprotected.
            assert_eq!(custom_code(PercolatorError::Unauthorized),              8);
            assert_eq!(custom_code(PercolatorError::InvalidInstruction),        9);
            assert_eq!(custom_code(PercolatorError::InvalidMint),              10);
            assert_eq!(custom_code(PercolatorError::InvalidTokenAccount),      11);
            assert_eq!(custom_code(PercolatorError::InvalidVaultAccount),      12);
            assert_eq!(custom_code(PercolatorError::InvalidTokenProgram),      13);

            // Engine errors — 14-25.
            assert_eq!(custom_code(PercolatorError::EngineInvalidConfig),      14);
            assert_eq!(custom_code(PercolatorError::EngineArithmeticOverflow), 15);
            assert_eq!(custom_code(PercolatorError::EngineProvenanceMismatch), 16);
            assert_eq!(custom_code(PercolatorError::EngineHiddenLeg),          17);
            assert_eq!(custom_code(PercolatorError::EngineInvalidLeg),         18);
            assert_eq!(custom_code(PercolatorError::EngineStale),              19);
            assert_eq!(custom_code(PercolatorError::EngineBStale),             20);
            assert_eq!(custom_code(PercolatorError::EngineLockActive),         21);
            assert_eq!(custom_code(PercolatorError::EngineNonProgress),        22);
            assert_eq!(custom_code(PercolatorError::EngineRecoveryRequired),   23);
            assert_eq!(custom_code(PercolatorError::EngineCounterOverflow),    24);
            assert_eq!(custom_code(PercolatorError::EngineCounterUnderflow),   25);

            // Oracle errors — 26-29. `InvalidOracleKey` (29) is the last
            // upstream variant; ordinal 30 must remain `LpVaultAlreadyExists`,
            // which is the boundary the test above starts from.
            assert_eq!(custom_code(PercolatorError::OracleInvalid),            26);
            assert_eq!(custom_code(PercolatorError::OracleStale),              27);
            assert_eq!(custom_code(PercolatorError::OracleConfTooWide),        28);
            assert_eq!(custom_code(PercolatorError::InvalidOracleKey),         29);
        }

        // ── F-1 cooldown gate (check_insurance_withdraw_cooldown) ────────────
        #[test]
        fn f1_cooldown_first_withdrawal_allowed_when_last_slot_zero() {
            // last_slot == 0 ⇒ never withdrawn ⇒ allowed regardless of the cooldown.
            assert!(check_insurance_withdraw_cooldown(100, 0, 0).is_ok());
            assert!(check_insurance_withdraw_cooldown(100, 0, 5).is_ok());
        }

        #[test]
        fn f1_cooldown_disabled_always_allows() {
            // cooldown == 0 ⇒ policy off ⇒ always allowed, even immediately after a withdrawal.
            assert!(check_insurance_withdraw_cooldown(0, 1_000, 1_000).is_ok());
            assert!(check_insurance_withdraw_cooldown(0, 1_000, 0).is_ok());
        }

        #[test]
        fn f1_cooldown_rejects_before_window_allows_at_or_after() {
            // last = 1000, cooldown = 100 ⇒ earliest allowed slot = 1100.
            assert_eq!(
                check_insurance_withdraw_cooldown(100, 1_000, 1_099).unwrap_err(),
                PercolatorError::InsuranceWithdrawCooldownActive.into()
            );
            assert!(check_insurance_withdraw_cooldown(100, 1_000, 1_100).is_ok()); // boundary inclusive
            assert!(check_insurance_withdraw_cooldown(100, 1_000, 1_200).is_ok());
        }

        #[test]
        fn f1_cooldown_overflow_rejected_not_panicked() {
            // last + cooldown overflows u64 ⇒ EngineArithmeticOverflow, never a panic.
            assert_eq!(
                check_insurance_withdraw_cooldown(u64::MAX, u64::MAX, 0).unwrap_err(),
                PercolatorError::EngineArithmeticOverflow.into()
            );
        }

        // ── F-2 deposits-only ceiling (apply_insurance_withdraw_ceiling) ─────
        #[test]
        fn f2_ceiling_disabled_returns_remaining_unchanged() {
            assert_eq!(apply_insurance_withdraw_ceiling(0, 50, 1_000).unwrap(), 50);
            assert_eq!(apply_insurance_withdraw_ceiling(0, 0, 0).unwrap(), 0);
        }

        #[test]
        fn f2_ceiling_enabled_decrements_and_enforces() {
            // amount <= remaining ⇒ decremented.
            assert_eq!(apply_insurance_withdraw_ceiling(1, 100, 40).unwrap(), 60);
            assert_eq!(apply_insurance_withdraw_ceiling(1, 100, 100).unwrap(), 0); // exact spend ok
            // amount > remaining ⇒ ceiling exceeded (no underflow).
            assert_eq!(
                apply_insurance_withdraw_ceiling(1, 100, 101).unwrap_err(),
                PercolatorError::InsuranceWithdrawCeilingExceeded.into()
            );
        }
    }
}

#[cfg(all(not(feature = "no-entrypoint"), not(feature = "anchor-v2")))]
pub mod entrypoint {
    use super::processor;
    #[allow(unused_imports)]
    use alloc::format;
    #[cfg(target_os = "solana")]
    use solana_program::entrypoint::{BumpAllocator, HEAP_START_ADDRESS};
    use solana_program::{
        account_info::AccountInfo,
        entrypoint::{deserialize, ProgramResult, SUCCESS},
        pubkey::Pubkey,
    };

    // The processor still materializes engine runtime structs. This remains
    // bounded at the current fixed asset cap; larger u16-indexed markets need
    // engine zero-copy/page APIs rather than larger fixed runtime arrays.
    pub const V16_HEAP_FRAME_BYTES: usize = 128 * 1024;

    #[cfg(target_os = "solana")]
    #[global_allocator]
    static A: BumpAllocator = BumpAllocator {
        start: HEAP_START_ADDRESS as usize,
        len: V16_HEAP_FRAME_BYTES,
    };

    solana_program::custom_panic_default!();

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
        let (program_id, accounts, instruction_data) = unsafe { deserialize(input) };
        match process_instruction(&program_id, &accounts, &instruction_data) {
            Ok(()) => SUCCESS,
            Err(error) => error.into(),
        }
    }

    fn process_instruction<'a>(
        program_id: &Pubkey,
        accounts: &'a [AccountInfo<'a>],
        instruction_data: &[u8],
    ) -> ProgramResult {
        processor::process_instruction(program_id, accounts, instruction_data)
    }
}

#[cfg(all(not(feature = "no-entrypoint"), feature = "anchor-v2"))]
#[allow(unsafe_code)]
pub mod entrypoint {
    extern crate alloc;

    use super::processor;
    use alloc::{rc::Rc, vec::Vec};
    use anchor_lang_v2::pinocchio::{
        account::{AccountView, RuntimeAccount},
        address::Address,
        entrypoint,
        error::ProgramError as AnchorProgramError,
        ProgramResult,
    };
    use core::{cell::RefCell, mem::size_of, slice::from_raw_parts_mut};
    use solana_program::{
        account_info::AccountInfo, clock::Epoch, program_error::ProgramError as LegacyProgramError,
        pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let program_id = Pubkey::new_from_array(program_id.to_bytes());
        process_with_legacy_account_infos(&program_id, accounts, instruction_data)
            .map_err(map_legacy_error)
    }

    #[inline(never)]
    fn process_with_legacy_account_infos(
        program_id: &Pubkey,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> Result<(), LegacyProgramError> {
        let len = accounts.len();
        let mut lamports = Vec::with_capacity(len);
        let mut data = Vec::with_capacity(len);

        for i in 0..len {
            if let Some(first) = first_duplicate(accounts, i) {
                lamports.push(Rc::clone(&lamports[first]));
                data.push(Rc::clone(&data[first]));
                continue;
            }

            let raw = accounts[i].account_mut_ptr();
            // Anchor v2 / Pinocchio owns the runtime account view. The v16
            // processor still uses AccountInfo internally, so this adapter is
            // the only compatibility bridge; persisted state serialization is
            // handled explicitly by `state`, not by raw Rust layout casts.
            let lamports_ref = unsafe { &mut (*raw).lamports };
            let data_ref = unsafe {
                from_raw_parts_mut(
                    (raw as *mut u8).add(size_of::<RuntimeAccount>()),
                    (*raw).data_len as usize,
                )
            };
            lamports.push(Rc::new(RefCell::new(lamports_ref)));
            data.push(Rc::new(RefCell::new(data_ref)));
        }

        let mut legacy_accounts = Vec::with_capacity(len);
        for (i, account) in accounts.iter().enumerate() {
            let key = unsafe { &*(account.address() as *const Address as *const Pubkey) };
            let owner = unsafe { &*(account.owner() as *const Address as *const Pubkey) };
            legacy_accounts.push(AccountInfo {
                key,
                lamports: Rc::clone(&lamports[i]),
                data: Rc::clone(&data[i]),
                owner,
                rent_epoch: Epoch::default(),
                is_signer: account.is_signer(),
                is_writable: account.is_writable(),
                executable: account.executable(),
            });
        }

        processor::process_instruction(program_id, &legacy_accounts, instruction_data)
    }

    fn first_duplicate(accounts: &[AccountView], index: usize) -> Option<usize> {
        let ptr = accounts[index].account_ptr();
        let mut i = 0;
        while i < index {
            if accounts[i].account_ptr() == ptr {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn map_legacy_error(error: LegacyProgramError) -> AnchorProgramError {
        match error {
            LegacyProgramError::Custom(code) => AnchorProgramError::Custom(code),
            LegacyProgramError::InvalidArgument => AnchorProgramError::InvalidArgument,
            LegacyProgramError::InvalidInstructionData => {
                AnchorProgramError::InvalidInstructionData
            }
            LegacyProgramError::InvalidAccountData => AnchorProgramError::InvalidAccountData,
            LegacyProgramError::AccountDataTooSmall => AnchorProgramError::AccountDataTooSmall,
            LegacyProgramError::InsufficientFunds => AnchorProgramError::InsufficientFunds,
            LegacyProgramError::IncorrectProgramId => AnchorProgramError::IncorrectProgramId,
            LegacyProgramError::MissingRequiredSignature => {
                AnchorProgramError::MissingRequiredSignature
            }
            LegacyProgramError::AccountAlreadyInitialized => {
                AnchorProgramError::AccountAlreadyInitialized
            }
            LegacyProgramError::UninitializedAccount => AnchorProgramError::UninitializedAccount,
            LegacyProgramError::NotEnoughAccountKeys => AnchorProgramError::NotEnoughAccountKeys,
            LegacyProgramError::AccountBorrowFailed => AnchorProgramError::AccountBorrowFailed,
            LegacyProgramError::MaxSeedLengthExceeded => AnchorProgramError::MaxSeedLengthExceeded,
            LegacyProgramError::InvalidSeeds => AnchorProgramError::InvalidSeeds,
            LegacyProgramError::BorshIoError(_) => AnchorProgramError::BorshIoError,
            LegacyProgramError::AccountNotRentExempt => AnchorProgramError::AccountNotRentExempt,
            LegacyProgramError::UnsupportedSysvar => AnchorProgramError::UnsupportedSysvar,
            LegacyProgramError::IllegalOwner => AnchorProgramError::IllegalOwner,
            LegacyProgramError::MaxAccountsDataAllocationsExceeded => {
                AnchorProgramError::MaxAccountsDataAllocationsExceeded
            }
            LegacyProgramError::InvalidRealloc => AnchorProgramError::InvalidRealloc,
            LegacyProgramError::MaxInstructionTraceLengthExceeded => {
                AnchorProgramError::MaxInstructionTraceLengthExceeded
            }
            LegacyProgramError::BuiltinProgramsMustConsumeComputeUnits => {
                AnchorProgramError::BuiltinProgramsMustConsumeComputeUnits
            }
            LegacyProgramError::InvalidAccountOwner => AnchorProgramError::InvalidAccountOwner,
            LegacyProgramError::ArithmeticOverflow => AnchorProgramError::ArithmeticOverflow,
        }
    }
}

pub mod risk {
    pub use percolator::*;
}
