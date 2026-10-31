//! v2.2 growth round 2, R2.1 item 4 (`~/percolator-ops/ledger/v22-growth-overnight-2026-10-14.md`):
//! the ON-CHAIN DEX depth source (depth source 2).
//!
//! Pure, integer-only and free of `AccountInfo` / syscalls (like `growth_v19`), so every function
//! is a Kani / proptest target. The processor gathers account bytes, calls these, and maps a
//! refusal (`None` / `false`) onto `DepthSourceInvalid` (129). `None` always means "fail closed".
//!
//! What lives here:
//! * the `DepthSourceV22` PDA record (`["depth_src", market]`, header kind 16): the upgrade
//!   authority's pin of one AMM pool (program, pool, both vaults, both mints) to one market asset;
//! * the pool parsers of the compile-time allow-list: PumpSwap AMM and Raydium CPMM (plus the
//!   devnet Raydium CPMM in a `devnet` build). Layouts verified against real mainnet accounts
//!   (`tests/fixtures/depth_src/`) and the programs' public IDL / source;
//! * SPL Token / Token-2022 token-account and mint parsers (Token-2022 mints: metadata / group
//!   extensions only);
//! * the all-or-nothing pin checker `pin_matches`;
//! * the exact +2% depth `plus2pct_depth_e6` (the keeper's algorithm, rounded DOWN);
//! * the collateral valuation `reserve_value_e6`.
//!
//! Depth (same as `keeper/src/cross-cluster/push-depth.ts::plus2PctDepthE6`):
//! ```text
//! depth = floor( R * (1 - 1/sqrt(1.02)) ) = R - m,   m = the smallest integer with 51 m^2 >= 50 R^2
//! ```
//! Valuation of `R` in collateral atoms (the market's "e6" unit):
//! ```text
//! quote mint == the market's primary collateral mint : R = quote reserve (atoms)
//! otherwise                                          : R = floor(base_reserve * mark_e6 / 10^(base_decimals + lot_exp))
//! ```
//! `mark_e6` is the per-LOT mark (a lot is `10^lot_exp` whole base tokens; `wave_a_v22`, item 7),
//! so `base_reserve / 10^(base_decimals + lot_exp)` is the reserve in lots. A constant-product pool
//! holds equal value on both sides at its own price, so the base side at the mark is the quote side.

use solana_program::pubkey::Pubkey;

// ── allow-list ─────────────────────────────────────────────────────────────────────────────

/// PumpSwap AMM (pump.fun). Verified: `idl/pump_amm.json` `address` in pump-fun/pump-public-docs
/// and the owner of the CHILLHOUSE / swordcat pools (fixtures). Same id on devnet.
pub const PUMPSWAP_AMM_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA");
/// Raydium CPMM (CP-Swap), mainnet. Verified: `declare_id!` (`not(feature = "devnet")`) in
/// raydium-io/raydium-cp-swap `programs/cp-swap/src/lib.rs` and the owner of the fixture pools.
pub const RAYDIUM_CPMM_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
/// Raydium CPMM, devnet deployment (`declare_id!` under `feature = "devnet"` in the same file;
/// an executable upgradeable program on devnet). Allowed only in a `devnet` build.
pub const RAYDIUM_CPMM_DEVNET_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("DRaycpLY18LhpbydsBWbVJtxpNv9oXPgjRSfpF2bWpYb");
/// SPL Token and Token-2022 (swordcat's mint and base vault are Token-2022).
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = spl_token::ID;
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// `DepthSourceV22::amm_kind`.
pub const AMM_PUMPSWAP: u8 = 1;
pub const AMM_RAYDIUM_CPMM: u8 = 2;

/// The AMM kind of a pool owner on the allow-list, `None` for any other program.
#[inline]
pub fn amm_kind_for_program(owner: &[u8; 32]) -> Option<u8> {
    if *owner == PUMPSWAP_AMM_PROGRAM_ID.to_bytes() {
        Some(AMM_PUMPSWAP)
    } else if *owner == RAYDIUM_CPMM_PROGRAM_ID.to_bytes()
        || (cfg!(feature = "devnet") && *owner == RAYDIUM_CPMM_DEVNET_PROGRAM_ID.to_bytes())
    {
        Some(AMM_RAYDIUM_CPMM)
    } else {
        None
    }
}

// ── pool layouts (offsets INCLUDE the 8-byte Anchor discriminator) ─────────────────────────

/// PumpSwap `Pool`: `sha256("account:Pool")[..8]` (= the IDL's `discriminator`).
pub const PUMPSWAP_POOL_DISC: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];
pub const PUMPSWAP_OFF_BASE_MINT: usize = 43;
pub const PUMPSWAP_OFF_QUOTE_MINT: usize = 75;
pub const PUMPSWAP_OFF_BASE_VAULT: usize = 139; // pool_base_token_account
pub const PUMPSWAP_OFF_QUOTE_VAULT: usize = 171; // pool_quote_token_account
/// `virtual_quote_reserves: i128` (SIGNED; may be negative: fees kept in the quote vault).
pub const PUMPSWAP_OFF_VIRTUAL_QUOTE: usize = 245;
pub const PUMPSWAP_OFF_PROTOCOL_FEES: usize = 271;
pub const PUMPSWAP_OFF_CREATOR_FEES: usize = 279;
/// The pool must carry at least the two vault keys. Appended fields absent on an older (shorter)
/// pool read as 0, as pump.fun documents ("read a missing field as 0").
pub const PUMPSWAP_POOL_MIN_LEN: usize = PUMPSWAP_OFF_QUOTE_VAULT + 32;

/// Raydium CPMM `PoolState` (`#[repr(C, packed)]`, `LEN = 637`): `sha256("account:PoolState")[..8]`.
pub const RAYDIUM_POOL_DISC: [u8; 8] = [247, 237, 227, 245, 215, 195, 222, 70];
pub const RAYDIUM_POOL_LEN: usize = 637;
pub const RAYDIUM_OFF_VAULT0: usize = 72;
pub const RAYDIUM_OFF_VAULT1: usize = 104;
pub const RAYDIUM_OFF_MINT0: usize = 168;
pub const RAYDIUM_OFF_MINT1: usize = 200;
pub const RAYDIUM_OFF_PROGRAM0: usize = 232;
pub const RAYDIUM_OFF_PROGRAM1: usize = 264;
pub const RAYDIUM_OFF_STATUS: usize = 329;
pub const RAYDIUM_OFF_PROTOCOL_FEES0: usize = 341;
pub const RAYDIUM_OFF_PROTOCOL_FEES1: usize = 349;
pub const RAYDIUM_OFF_FUND_FEES0: usize = 357;
pub const RAYDIUM_OFF_FUND_FEES1: usize = 365;
pub const RAYDIUM_OFF_CREATOR_FEES0: usize = 397;
pub const RAYDIUM_OFF_CREATOR_FEES1: usize = 405;
/// `PoolStatusBitIndex::Swap` = bit 2: set means swaps are DISABLED (no real depth).
pub const RAYDIUM_STATUS_SWAP_DISABLED: u8 = 1 << 2;

#[inline]
fn key_at(data: &[u8], off: usize) -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    k.copy_from_slice(data.get(off..off.checked_add(32)?)?);
    Some(k)
}

#[inline]
fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    b.copy_from_slice(data.get(off..off.checked_add(8)?)?);
    Some(u64::from_le_bytes(b))
}

/// u64 at `off`, or 0 when the account is too short to carry the field (an appended field).
#[inline]
fn u64_at_or_zero(data: &[u8], off: usize) -> u64 {
    u64_at(data, off).unwrap_or(0)
}

/// The two sides of a pool in the pool's own order (PumpSwap: 0 = base, 1 = quote; Raydium CPMM:
/// 0 = token_0, 1 = token_1). `token_program[i]` is the side's token program when the pool
/// records it (Raydium), else `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSides {
    pub mint: [[u8; 32]; 2],
    pub vault: [[u8; 32]; 2],
    pub token_program: [Option<[u8; 32]>; 2],
}

/// Parses a pool of `amm_kind`: discriminator, length, both mints and both vault keys. `None` on a
/// wrong discriminator, a short account, or a pool whose two mints / two vaults coincide.
pub fn parse_pool(amm_kind: u8, data: &[u8]) -> Option<PoolSides> {
    let sides = match amm_kind {
        AMM_PUMPSWAP => {
            if data.len() < PUMPSWAP_POOL_MIN_LEN || data.get(0..8)? != PUMPSWAP_POOL_DISC {
                return None;
            }
            PoolSides {
                mint: [
                    key_at(data, PUMPSWAP_OFF_BASE_MINT)?,
                    key_at(data, PUMPSWAP_OFF_QUOTE_MINT)?,
                ],
                vault: [
                    key_at(data, PUMPSWAP_OFF_BASE_VAULT)?,
                    key_at(data, PUMPSWAP_OFF_QUOTE_VAULT)?,
                ],
                token_program: [None, None],
            }
        }
        AMM_RAYDIUM_CPMM => {
            if data.len() != RAYDIUM_POOL_LEN || data.get(0..8)? != RAYDIUM_POOL_DISC {
                return None;
            }
            PoolSides {
                mint: [key_at(data, RAYDIUM_OFF_MINT0)?, key_at(data, RAYDIUM_OFF_MINT1)?],
                vault: [key_at(data, RAYDIUM_OFF_VAULT0)?, key_at(data, RAYDIUM_OFF_VAULT1)?],
                token_program: [
                    Some(key_at(data, RAYDIUM_OFF_PROGRAM0)?),
                    Some(key_at(data, RAYDIUM_OFF_PROGRAM1)?),
                ],
            }
        }
        _ => return None,
    };
    if sides.mint[0] == sides.mint[1]
        || sides.vault[0] == sides.vault[1]
        || sides.mint.contains(&[0u8; 32])
        || sides.vault.contains(&[0u8; 32])
    {
        return None;
    }
    Some(sides)
}

/// The trading reserves of a pool, in the pool's side order, from the two vault balances.
/// * PumpSwap: base = the raw base vault balance (pump.fun: "base reserves are still the raw
///   `pool_base_token_account.amount`"). Quote = the SMALLER of the effective quote reserve
///   `vault + virtual_quote_reserves` (signed; what swaps are priced on) and the real quote
///   `vault - protocol_fees - creator_fees` (fees waiting in the vault are not liquidity, and a
///   boost is not real tokens). So the quote side is never overstated.
/// * Raydium CPMM: each side = vault - (protocol + fund + creator fees of that side)
///   (`PoolState::vault_amount_without_fee`). A pool with swaps disabled is refused.
///
/// `None` (fail closed): an underflow, a negative / over-u64 effective reserve, an unknown kind.
pub fn pool_reserves(amm_kind: u8, data: &[u8], vault_amounts: [u64; 2]) -> Option<[u64; 2]> {
    match amm_kind {
        AMM_PUMPSWAP => {
            if data.len() < PUMPSWAP_POOL_MIN_LEN {
                return None;
            }
            let vq: i128 = match data.get(PUMPSWAP_OFF_VIRTUAL_QUOTE..PUMPSWAP_OFF_VIRTUAL_QUOTE + 16) {
                Some(b) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    i128::from_le_bytes(a)
                }
                None => 0,
            };
            let effective = (vault_amounts[1] as i128).checked_add(vq)?;
            if effective < 0 || effective > u64::MAX as i128 {
                return None;
            }
            let real = vault_amounts[1]
                .checked_sub(u64_at_or_zero(data, PUMPSWAP_OFF_PROTOCOL_FEES))?
                .checked_sub(u64_at_or_zero(data, PUMPSWAP_OFF_CREATOR_FEES))?;
            let quote = core::cmp::min(effective as u64, real);
            Some([vault_amounts[0], quote])
        }
        AMM_RAYDIUM_CPMM => {
            if data.len() != RAYDIUM_POOL_LEN {
                return None;
            }
            if data[RAYDIUM_OFF_STATUS] & RAYDIUM_STATUS_SWAP_DISABLED != 0 {
                return None;
            }
            let fees0 = u64_at(data, RAYDIUM_OFF_PROTOCOL_FEES0)?
                .checked_add(u64_at(data, RAYDIUM_OFF_FUND_FEES0)?)?
                .checked_add(u64_at(data, RAYDIUM_OFF_CREATOR_FEES0)?)?;
            let fees1 = u64_at(data, RAYDIUM_OFF_PROTOCOL_FEES1)?
                .checked_add(u64_at(data, RAYDIUM_OFF_FUND_FEES1)?)?
                .checked_add(u64_at(data, RAYDIUM_OFF_CREATOR_FEES1)?)?;
            Some([
                vault_amounts[0].checked_sub(fees0)?,
                vault_amounts[1].checked_sub(fees1)?,
            ])
        }
        _ => None,
    }
}

// ── SPL Token / Token-2022 ─────────────────────────────────────────────────────────────────

pub const TOKEN_ACCOUNT_BASE_LEN: usize = 165;
pub const MINT_BASE_LEN: usize = 82;
/// Token-2022 `AccountType` byte (at offset 165 of an extended account).
pub const T22_ACCOUNT_TYPE_MINT: u8 = 1;
pub const T22_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
/// Token-2022 mint extensions accepted for a pinned mint: metadata / group pointers and data
/// (`ExtensionType` 18..=23). Everything else (transfer fee, transfer hook, permanent delegate,
/// pausable, default-frozen, non-transferable, confidential, interest / scaled UI, close authority)
/// is refused: those change what the vault balance is worth or whether the pool can trade.
pub const T22_MINT_EXT_ALLOWED_MIN: u16 = 18;
pub const T22_MINT_EXT_ALLOWED_MAX: u16 = 23;

/// A parsed token account: mint and amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAcct {
    pub mint: [u8; 32],
    pub amount: u64,
}

#[inline]
pub fn is_token_program(owner: &[u8; 32]) -> bool {
    *owner == SPL_TOKEN_PROGRAM_ID.to_bytes() || *owner == TOKEN_2022_PROGRAM_ID.to_bytes()
}

/// A token account owned by SPL Token (exactly 165 B) or Token-2022 (165 B, or extended with
/// `AccountType::Account`), in state Initialized (a frozen vault cannot trade: refused).
pub fn parse_token_account(owner: &[u8; 32], data: &[u8]) -> Option<TokenAcct> {
    if !is_token_program(owner) || data.len() < TOKEN_ACCOUNT_BASE_LEN {
        return None;
    }
    if data.len() > TOKEN_ACCOUNT_BASE_LEN
        && (*owner != TOKEN_2022_PROGRAM_ID.to_bytes()
            || data[TOKEN_ACCOUNT_BASE_LEN] != T22_ACCOUNT_TYPE_ACCOUNT)
    {
        return None;
    }
    // AccountState: 0 Uninitialized, 1 Initialized, 2 Frozen.
    if data[108] != 1 {
        return None;
    }
    Some(TokenAcct {
        mint: key_at(data, 0)?,
        amount: u64_at(data, 64)?,
    })
}

/// The decimals of an initialized mint owned by SPL Token (exactly 82 B) or Token-2022 (82 B, or
/// extended: zero padding to 165, `AccountType::Mint`, then only allowed TLV extensions, walked to
/// the end). `None` otherwise.
pub fn parse_mint(owner: &[u8; 32], data: &[u8]) -> Option<u8> {
    if !is_token_program(owner) || data.len() < MINT_BASE_LEN || data[45] != 1 {
        return None;
    }
    if data.len() != MINT_BASE_LEN {
        if *owner != TOKEN_2022_PROGRAM_ID.to_bytes()
            || data.len() <= TOKEN_ACCOUNT_BASE_LEN
            || data[MINT_BASE_LEN..TOKEN_ACCOUNT_BASE_LEN].iter().any(|b| *b != 0)
            || data[TOKEN_ACCOUNT_BASE_LEN] != T22_ACCOUNT_TYPE_MINT
        {
            return None;
        }
        let mut i = TOKEN_ACCOUNT_BASE_LEN + 1;
        while i < data.len() {
            let hdr = data.get(i..i.checked_add(4)?)?;
            let t = u16::from_le_bytes([hdr[0], hdr[1]]);
            let l = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
            if t == 0 {
                // Uninitialized: the rest must be zero padding.
                if data[i..].iter().any(|b| *b != 0) {
                    return None;
                }
                break;
            }
            if !(T22_MINT_EXT_ALLOWED_MIN..=T22_MINT_EXT_ALLOWED_MAX).contains(&t) {
                return None;
            }
            i = i.checked_add(4)?.checked_add(l)?;
            if i > data.len() {
                return None;
            }
        }
    }
    Some(data[44])
}

// ── the PDA record ─────────────────────────────────────────────────────────────────────────

pub const DEPTH_SOURCE_SEED: &[u8] = b"depth_src";
pub const DEPTH_SOURCE_VERSION: u8 = 1;
/// `flags` bit 0: the pin is in force. Clear (0) after a UA "clear": mode 2 is refused (129).
pub const DEPTH_SRC_FLAG_ACTIVE: u8 = 1 << 0;
/// `flags` bit 1: the market's asset ("base") is the pool's side 1 (else side 0). PumpSwap pools
/// list the coin as side 0; a Raydium CPMM orders its sides by mint key, so either is possible.
pub const DEPTH_SRC_FLAG_BASE_IS_SIDE1: u8 = 1 << 1;
pub const DEPTH_SRC_FLAGS_KNOWN: u8 = DEPTH_SRC_FLAG_ACTIVE | DEPTH_SRC_FLAG_BASE_IS_SIDE1;
/// Mint decimals above this are refused (keeps `10^(decimals + lot_exp)` inside u128).
pub const DEPTH_SRC_MAX_DECIMALS: u8 = 18;

/// `["depth_src", market]`, header kind 16 (`constants::KIND_DEPTH_SOURCE`), body at `HEADER_LEN`.
/// One per market account (slab): it pins ONE asset (`asset_index`, generation `market_id`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DepthSourceV22 {
    pub market: [u8; 32],      // 0..32   the market (slab) account key
    pub amm_program: [u8; 32], // 32..64  the pool's owner (allow-listed)
    pub pool: [u8; 32],        // 64..96
    pub base_vault: [u8; 32],  // 96..128  the pool's vault of the market's asset
    pub quote_vault: [u8; 32], // 128..160
    pub base_mint: [u8; 32],   // 160..192
    pub quote_mint: [u8; 32],  // 192..224
    pub market_id: u64,        // 224..232 the pinned asset generation
    pub set_slot: u64,         // 232..240 slot of the last SetDepthSource (informational)
    pub asset_index: u16,      // 240..242
    pub base_decimals: u8,     // 242
    pub quote_decimals: u8,    // 243
    pub flags: u8,             // 244
    pub version: u8,           // 245
    pub bump: u8,              // 246
    pub amm_kind: u8,          // 247
    pub _reserved: [u8; 8],    // 248..256
}
const _: () = assert!(core::mem::size_of::<DepthSourceV22>() == 256);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, amm_program) == 32);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, pool) == 64);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, base_vault) == 96);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, quote_vault) == 128);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, base_mint) == 160);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, quote_mint) == 192);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, market_id) == 224);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, set_slot) == 232);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, asset_index) == 240);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, base_decimals) == 242);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, quote_decimals) == 243);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, flags) == 244);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, version) == 245);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, bump) == 246);
const _: () = assert!(core::mem::offset_of!(DepthSourceV22, amm_kind) == 247);

impl DepthSourceV22 {
    #[inline]
    pub fn is_active(&self) -> bool {
        self.flags & DEPTH_SRC_FLAG_ACTIVE != 0
    }
    /// `(base side, quote side)` indices into `PoolSides`.
    #[inline]
    pub fn sides(&self) -> (usize, usize) {
        if self.flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 {
            (1, 0)
        } else {
            (0, 1)
        }
    }
    /// The cleared form: everything but `market`, `version`, `bump` zero.
    pub fn cleared(market: [u8; 32], bump: u8) -> Self {
        DepthSourceV22 {
            market,
            version: DEPTH_SOURCE_VERSION,
            bump,
            ..Default::default()
        }
    }
}

/// Structural validation of a stored record. Active: allow-listed program of the recorded kind,
/// every key non-zero, distinct mints and vaults, bounded decimals. Cleared: every pin field zero.
pub fn validate_depth_source(x: &DepthSourceV22) -> bool {
    if x.version != DEPTH_SOURCE_VERSION
        || x.market == [0u8; 32]
        || x._reserved != [0u8; 8]
        || x.flags & !DEPTH_SRC_FLAGS_KNOWN != 0
    {
        return false;
    }
    if !x.is_active() {
        return *x == DepthSourceV22::cleared(x.market, x.bump);
    }
    let z = [0u8; 32];
    amm_kind_for_program(&x.amm_program) == Some(x.amm_kind)
        && x.pool != z
        && x.base_vault != z
        && x.quote_vault != z
        && x.base_mint != z
        && x.quote_mint != z
        && x.base_mint != x.quote_mint
        && x.base_vault != x.quote_vault
        && x.base_decimals <= DEPTH_SRC_MAX_DECIMALS
        && x.quote_decimals <= DEPTH_SRC_MAX_DECIMALS
}

/// The orientation of the given (base vault, quote vault) inside a parsed pool, as the
/// `DEPTH_SRC_FLAG_BASE_IS_SIDE1` bit: `Some(0)` = base is side 0, `Some(flag)` = side 1, `None`
/// when the two vaults are not exactly the pool's two vaults with the given mints.
pub fn orientation(
    sides: &PoolSides,
    base_vault: &[u8; 32],
    quote_vault: &[u8; 32],
    base_mint: &[u8; 32],
    quote_mint: &[u8; 32],
) -> Option<u8> {
    for (b, q, flag) in [(0usize, 1usize, 0u8), (1, 0, DEPTH_SRC_FLAG_BASE_IS_SIDE1)] {
        if sides.vault[b] == *base_vault
            && sides.vault[q] == *quote_vault
            && sides.mint[b] == *base_mint
            && sides.mint[q] == *quote_mint
        {
            return Some(flag);
        }
    }
    None
}

/// What PushAuthMark mode 2 sees: the accounts it was given, already parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushView {
    /// The market account key, the asset index and generation of the push.
    pub market: [u8; 32],
    pub asset_index: u16,
    pub market_id: u64,
    pub pool_key: [u8; 32],
    pub pool_owner: [u8; 32],
    pub sides: PoolSides,
    pub base_vault_key: [u8; 32],
    pub quote_vault_key: [u8; 32],
    /// Owner programs of the two vault accounts.
    pub base_vault_program: [u8; 32],
    pub quote_vault_program: [u8; 32],
    pub base_vault: TokenAcct,
    pub quote_vault: TokenAcct,
}

/// The all-or-nothing pin check of PushAuthMark mode 2: `true` only when EVERY one of these holds
/// (the record itself must already have passed `validate_depth_source`):
/// * the pin is active and pins this market, asset and generation;
/// * the pool's owner is the pinned AMM program, on the allow-list with the pinned kind, and the
///   pool key is the pinned pool;
/// * the two vault keys are the pinned ones AND the pool's own vault fields (in the pinned
///   orientation);
/// * the pool's own mints, the pinned mints and the vault accounts' mints all agree per side;
/// * where the pool records a side's token program (Raydium), the vault is owned by it.
pub fn pin_matches(pin: &DepthSourceV22, v: &PushView) -> bool {
    let (b, q) = pin.sides();
    let prog_ok = |side: usize, owner: &[u8; 32]| match v.sides.token_program[side] {
        Some(p) => p == *owner,
        None => true,
    };
    pin.is_active()
        && pin.market == v.market
        && pin.asset_index == v.asset_index
        && pin.market_id == v.market_id
        && v.pool_owner == pin.amm_program
        && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
        && v.pool_key == pin.pool
        && v.base_vault_key == pin.base_vault
        && v.quote_vault_key == pin.quote_vault
        && v.sides.vault[b] == pin.base_vault
        && v.sides.vault[q] == pin.quote_vault
        && v.sides.mint[b] == pin.base_mint
        && v.sides.mint[q] == pin.quote_mint
        && v.base_vault.mint == pin.base_mint
        && v.quote_vault.mint == pin.quote_mint
        && prog_ok(b, &v.base_vault_program)
        && prog_ok(q, &v.quote_vault_program)
}

// ── depth math ─────────────────────────────────────────────────────────────────────────────

/// `floor(sqrt(n))`, exact (Newton from a power-of-two over-estimate; at most ~8 iterations).
pub fn isqrt_u128(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let bits = 128 - n.leading_zeros();
    let mut x: u128 = 1u128 << bits.div_ceil(2); // >= sqrt(n), <= 2^64
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// `51 m^2 >= 50 r^2` evaluated exactly in u128 for every `m <= r <= u64::MAX`:
/// with `a = m^2`, `q = r^2`: true when `a >= q`, else `51a >= 50q  <=>  50(q - a) <= a
/// <=>  q - a <= floor(a / 50)`.
#[inline]
pub fn depth_pred(m: u64, r: u64) -> bool {
    let a = (m as u128) * (m as u128);
    let q = (r as u128) * (r as u128);
    if a >= q {
        return true;
    }
    q - a <= a / 50
}

/// The exact +2% depth of a constant-product pool from a reserve `r` valued in collateral atoms:
/// `floor(r * (1 - 1/sqrt(1.02))) = r - m`, `m` the smallest integer with `51 m^2 >= 50 r^2`.
/// Rounded DOWN (never overstated); full u64 width, no overflow, no float. Identical to the
/// keeper's `plus2PctDepthE6`.
pub fn plus2pct_depth_e6(r: u64) -> u64 {
    if r == 0 {
        return 0;
    }
    let q = (r as u128) * (r as u128);
    // floor(50 q / 51) = q - ceil(q / 51)
    let t = q - q.div_ceil(51);
    // m0 = floor(sqrt(t)): 51 m0^2 <= 50 q, and 51 (m0+1)^2 > 50 q, so m is m0 or m0 + 1.
    let m0 = isqrt_u128(t) as u64; // m0 < r
    let m = if depth_pred(m0, r) { m0 } else { m0 + 1 };
    r - m
}

/// Which side gives the reserve value (see the module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValuePath {
    /// The quote mint is the market's collateral mint: the quote reserve in atoms.
    QuoteIsCollateral,
    /// Otherwise: the base reserve at the market's per-lot mark.
    BaseAtMark,
}

/// The reserve value `R` in collateral atoms. `BaseAtMark`:
/// `floor(base_atoms * mark_e6 / 10^(base_decimals + lot_exp))`, capped at `u64::MAX` (a cap only
/// lowers the depth). `None` when the exponent is out of range (decimals > 18 or lot_exp > 15;
/// both refused earlier) or the mark is 0.
pub fn reserve_value_e6(
    path: ValuePath,
    base_atoms: u64,
    quote_atoms: u64,
    mark_e6: u64,
    base_decimals: u8,
    lot_exp: u8,
) -> Option<u64> {
    match path {
        ValuePath::QuoteIsCollateral => Some(quote_atoms),
        ValuePath::BaseAtMark => {
            if mark_e6 == 0
                || base_decimals > DEPTH_SRC_MAX_DECIMALS
                || lot_exp > crate::constants::LOT_EXP_MAX
            {
                return None;
            }
            let e = base_decimals as u32 + lot_exp as u32; // <= 33
            let v = (base_atoms as u128) * (mark_e6 as u128) / 10u128.pow(e);
            Some(if v > u64::MAX as u128 { u64::MAX } else { v as u64 })
        }
    }
}

// ── PushAuthMark depth-mode decode ─────────────────────────────────────────────────────────

/// The decoded 44-byte depth tail of PushAuthMark (tag 63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepthMode {
    /// mode 0: no depth (`depth_e6` must be 0).
    None,
    /// mode 1: keeper-attested `depth_e6`.
    Attested(u64),
    /// mode 2: on-chain DEX (`depth_e6` must be 0; the program computes it from the pool).
    Dex,
}

pub const DEPTH_MODE_DEX: u8 = 2;

/// Mode decode: `None` (refuse with `DepthInputInvalid`, 128) for any other mode, or for mode 0 /
/// mode 2 with a non-zero `depth_e6`.
#[inline]
pub fn decode_depth_mode(mode: u8, depth_e6: u64) -> Option<DepthMode> {
    match (mode, depth_e6) {
        (0, 0) => Some(DepthMode::None),
        (1, d) => Some(DepthMode::Attested(d)),
        (DEPTH_MODE_DEX, 0) => Some(DepthMode::Dex),
        _ => None,
    }
}

/// Kani harnesses (R2.1 item 4). WRITTEN, NOT RUN in this change (run locally, one at a time:
/// `cargo kani --lib --features devnet -Z stubbing --harness <name>`; docs/KANI.md). Inputs are bounded (u32 reserves, symbolic keys); the
/// full-width claims are the proptests in `tests/v22_dex_depth.rs` (neither alone is the claim).
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The depth is the EXACT floor of `R (1 - 1/sqrt(1.02))` for every u32 reserve:
    /// `m = R - depth` is the smallest integer with `51 m^2 >= 50 R^2` (so the depth is never
    /// overstated and never more than 1 atom under the real value), and `depth < R/100`.
    /// Mutants killed: `m = m0` always (skip the +1 branch); `m0 + 1` always; ceil instead of
    /// floor in `t` (`q - q/51`); `R - m - 1`; `>` for `>=` in `depth_pred`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_dex_depth_floor_exact() {
        let r32: u32 = kani::any();
        let r = r32 as u64;
        let d = plus2pct_depth_e6(r);
        assert!(d <= r);
        let m = (r - d) as u128;
        let q = (r as u128) * (r as u128);
        assert!(51 * m * m >= 50 * q, "m large enough: depth never overstated");
        assert!(m == 0 || 51 * (m - 1) * (m - 1) < 50 * q, "m minimal: depth is the floor");
        assert!(d as u128 * 100 <= r as u128, "under 1% of the reserve");
        kani::cover!(r == 0 && d == 0, "zero reserve");
        kani::cover!(r > 0 && r < 102 && d == 0, "sub-atom depth floors to 0");
        kani::cover!(d > 0, "positive depth");
        kani::cover!(r > 1 << 31, "top of the u32 range");
    }

    /// `isqrt_u128` is the exact floor square root (u64 inputs: every `t` a u32 reserve makes).
    /// Mutants killed: return `y` instead of `x`; `y > x` for `y >= x`; start below sqrt(n).
    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_dex_isqrt_exact_u64() {
        let n64: u64 = kani::any();
        let n = n64 as u128;
        let x = isqrt_u128(n);
        assert!(x * x <= n);
        assert!((x + 1) * (x + 1) > n);
    }

    fn any_key() -> [u8; 32] {
        kani::any()
    }

    /// The pin check is all-or-nothing: `pin_matches` holds IFF every one of its conjuncts holds
    /// (pin active, market / asset / generation, pool owner == pinned program AND allow-listed of
    /// the pinned kind, pool key, both vault keys == pinned == the pool's own fields in the
    /// pinned orientation, the pool's mints == the pinned mints == the vault accounts' mints, the
    /// recorded token programs). Symbolic keys throughout.
    /// Mutants killed: drop any one conjunct (e.g. the pool's own vault field, the vault
    /// account's mint, the orientation, the allow-list), compare against the wrong side.
    #[kani::proof]
    fn kani_dex_pin_check_all_or_nothing() {
        let pin = DepthSourceV22 {
            market: any_key(),
            amm_program: any_key(),
            pool: any_key(),
            base_vault: any_key(),
            quote_vault: any_key(),
            base_mint: any_key(),
            quote_mint: any_key(),
            market_id: kani::any(),
            set_slot: 0,
            asset_index: kani::any(),
            base_decimals: kani::any(),
            quote_decimals: kani::any(),
            flags: kani::any(),
            version: DEPTH_SOURCE_VERSION,
            bump: kani::any(),
            amm_kind: kani::any(),
            _reserved: [0; 8],
        };
        let v = PushView {
            market: any_key(),
            asset_index: kani::any(),
            market_id: kani::any(),
            pool_key: any_key(),
            pool_owner: any_key(),
            sides: PoolSides {
                mint: [any_key(), any_key()],
                vault: [any_key(), any_key()],
                token_program: [kani::any::<bool>().then(any_key), kani::any::<bool>().then(any_key)],
            },
            base_vault_key: any_key(),
            quote_vault_key: any_key(),
            base_vault_program: any_key(),
            quote_vault_program: any_key(),
            base_vault: TokenAcct { mint: any_key(), amount: kani::any() },
            quote_vault: TokenAcct { mint: any_key(), amount: kani::any() },
        };
        let ok = pin_matches(&pin, &v);
        let (b, q) = if pin.flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 { (1, 0) } else { (0, 1) };
        let prog = |side: usize, o: &[u8; 32]| v.sides.token_program[side].map_or(true, |p| p == *o);
        let all = pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0
            && pin.market == v.market
            && pin.asset_index == v.asset_index
            && pin.market_id == v.market_id
            && v.pool_owner == pin.amm_program
            && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
            && v.pool_key == pin.pool
            && v.base_vault_key == pin.base_vault
            && v.quote_vault_key == pin.quote_vault
            && v.sides.vault[b] == pin.base_vault
            && v.sides.vault[q] == pin.quote_vault
            && v.sides.mint[b] == pin.base_mint
            && v.sides.mint[q] == pin.quote_mint
            && v.base_vault.mint == pin.base_mint
            && v.quote_vault.mint == pin.quote_mint
            && prog(b, &v.base_vault_program)
            && prog(q, &v.quote_vault_program);
        assert_eq!(ok, all);
        if ok {
            // the vault accounts ARE the pool's own vaults, in the pinned orientation
            assert!(v.base_vault_key == v.sides.vault[b] && v.quote_vault_key == v.sides.vault[q]);
            assert!(v.pool_owner == PUMPSWAP_AMM_PROGRAM_ID.to_bytes() || v.pool_owner == RAYDIUM_CPMM_PROGRAM_ID.to_bytes()
                || (cfg!(feature = "devnet") && v.pool_owner == RAYDIUM_CPMM_DEVNET_PROGRAM_ID.to_bytes()));
        }
        kani::cover!(ok, "a matching view is accepted");
        kani::cover!(!ok && all_but_vault_field(&pin, &v, b), "only the pool's own vault field differs");
    }

    /// Every conjunct but `sides.vault[b] == pin.base_vault` (a cover helper).
    fn all_but_vault_field(pin: &DepthSourceV22, v: &PushView, b: usize) -> bool {
        let q = 1 - b;
        pin.is_active()
            && pin.market == v.market
            && v.pool_owner == pin.amm_program
            && v.pool_key == pin.pool
            && v.base_vault_key == pin.base_vault
            && v.sides.vault[b] != pin.base_vault
            && v.sides.vault[q] == pin.quote_vault
    }

    /// The tag-63 depth-mode decode, exhaustively: exactly (0, 0) -> none, (1, d) -> attested d,
    /// (2, 0) -> DEX; every other (mode, depth) is refused (128). And the stored source for each
    /// decoded mode is the matching `growth_v19::DEPTH_SOURCE_*` (0 / 1 / 2).
    /// Mutants killed: accept mode 2 with a wire depth; accept mode 3; mode 0 with a depth.
    #[kani::proof]
    fn kani_dex_mode_decode_exhaustive() {
        let mode: u8 = kani::any();
        let d: u64 = kani::any();
        let r = decode_depth_mode(mode, d);
        match r {
            Some(DepthMode::None) => assert!(mode == 0 && d == 0),
            Some(DepthMode::Attested(x)) => assert!(mode == 1 && x == d),
            Some(DepthMode::Dex) => assert!(mode == 2 && d == 0),
            None => assert!(!((mode == 0 && d == 0) || mode == 1 || (mode == 2 && d == 0))),
        }
        assert_eq!(crate::growth_v19::DEPTH_MODE_DEX, DEPTH_MODE_DEX);
        assert_eq!(crate::growth_v19::DEPTH_SOURCE_DEX, DEPTH_MODE_DEX);
        kani::cover!(mode == 2 && d == 0 && r == Some(DepthMode::Dex), "mode 2 decodes");
        kani::cover!(mode == 2 && d != 0 && r.is_none(), "mode 2 with a wire depth refused");
        kani::cover!(mode >= 3 && r.is_none(), "unknown mode refused");
    }

    /// Valuation: `BaseAtMark` is the exact floor of `base * mark / 10^(dec + lot)`, capped at
    /// u64::MAX (never above the exact value); out-of-range exponents / a zero mark refuse.
    /// Bounded: u32 base and mark. Mutants killed: round up; ignore `lot_exp`; ignore decimals.
    #[kani::proof]
    fn kani_dex_valuation_floor() {
        let base: u32 = kani::any();
        let mark: u32 = kani::any();
        let dec: u8 = kani::any();
        let lot: u8 = kani::any();
        kani::assume(dec <= 20 && lot <= 16);
        let v = reserve_value_e6(ValuePath::BaseAtMark, base as u64, 0, mark as u64, dec, lot);
        if mark == 0 || dec > DEPTH_SRC_MAX_DECIMALS || lot > crate::constants::LOT_EXP_MAX {
            assert!(v.is_none());
        } else {
            let p = 10u128.pow(dec as u32 + lot as u32);
            let x = v.unwrap() as u128;
            assert!(x * p <= base as u128 * mark as u128);
            assert!((x + 1) * p > base as u128 * mark as u128);
        }
        kani::cover!(v == Some(0) && base > 0 && mark > 0, "value floors to 0");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeper_vectors() {
        for (r, want) in [
            (1_000_000u64 * 1_000_000, 9_852_457_023u64),
            (25_000 * 1_000_000, 246_311_425),
            (123_456_789, 1_216_352),
            (0, 0),
            (1, 0),
            (100, 0),
            (102, 1),
            (u64::MAX, 181_745_753_206_511_237),
        ] {
            assert_eq!(plus2pct_depth_e6(r), want, "R={r}");
        }
    }

    #[test]
    fn isqrt_exact_small_and_edges() {
        for n in 0u128..10_000 {
            let r = isqrt_u128(n);
            assert!(r * r <= n && (r + 1) * (r + 1) > n);
        }
        for n in [u128::MAX, u128::MAX - 1, ((1u128 << 64) - 1) * ((1u128 << 64) - 1), 1u128 << 127] {
            let r = isqrt_u128(n);
            assert!(r.checked_mul(r).unwrap() <= n);
            assert!((r + 1).checked_mul(r + 1).map_or(true, |s| s > n));
        }
    }

    #[test]
    fn mode_decode_table() {
        assert_eq!(decode_depth_mode(0, 0), Some(DepthMode::None));
        assert_eq!(decode_depth_mode(0, 1), None);
        assert_eq!(decode_depth_mode(1, 0), Some(DepthMode::Attested(0)));
        assert_eq!(decode_depth_mode(1, 7), Some(DepthMode::Attested(7)));
        assert_eq!(decode_depth_mode(2, 0), Some(DepthMode::Dex));
        assert_eq!(decode_depth_mode(2, 1), None);
        for m in 3..=255u8 {
            assert_eq!(decode_depth_mode(m, 0), None);
        }
    }

    #[test]
    fn valuation_chillhouse_lot_exp_4() {
        // CHILLHOUSE ~ $0.0012 per token, lot_exp 4: a lot is 10^4 tokens = $12, mark_e6 = 12e6.
        // Base reserve 171,449,177.380421 tokens (6 decimals) -> $205,739.012856.
        let v = reserve_value_e6(ValuePath::BaseAtMark, 171_449_177_380_421, 0, 12_000_000, 6, 4);
        assert_eq!(v, Some(205_739_012_856));
        assert_eq!(plus2pct_depth_e6(205_739_012_856), 2_027_034_782); // ~ $2,027.03: tier 0
        assert_eq!(reserve_value_e6(ValuePath::BaseAtMark, 1, 0, 0, 6, 4), None);
        assert_eq!(reserve_value_e6(ValuePath::BaseAtMark, 1, 0, 1, 19, 0), None);
        assert_eq!(reserve_value_e6(ValuePath::BaseAtMark, 1, 0, 1, 0, 16), None);
        assert_eq!(reserve_value_e6(ValuePath::BaseAtMark, u64::MAX, 0, u64::MAX, 0, 0), Some(u64::MAX));
        assert_eq!(reserve_value_e6(ValuePath::QuoteIsCollateral, 5, 9, 0, 99, 99), Some(9));
    }
}

// ── decision 16 (night 2026-10-28): one growth market per spot pool ─────────────────────────

/// `["pool_claim", pool]`, header kind 18 (`constants::KIND_POOL_CLAIM`), body at `HEADER_LEN`. The pool a
/// market's depth-source pin reads is CLAIMED by that market: tag 123 refuses to pin a pool another market
/// holds (plan v2 decision 16 / G6 / G11: two markets sizing capacity off one pool's depth double-count it,
/// and one pool push moves both). Created at the pin, released when the pin clears or moves to another pool.
pub const POOL_CLAIM_SEED: &[u8] = b"pool_claim";
pub const POOL_CLAIM_VERSION: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct PoolClaimV22 {
    pub pool: [u8; 32],      // 0..32
    pub market: [u8; 32],    // 32..64  the claiming market (slab) key
    pub asset_index: u16,    // 64..66
    pub version: u8,         // 66
    pub bump: u8,            // 67
    pub _reserved: [u8; 12], // 68..80
}
const _: () = assert!(core::mem::size_of::<PoolClaimV22>() == 80);
const _: () = assert!(core::mem::offset_of!(PoolClaimV22, market) == 32);
const _: () = assert!(core::mem::offset_of!(PoolClaimV22, asset_index) == 64);

pub fn validate_pool_claim(c: &PoolClaimV22) -> bool {
    c.version == POOL_CLAIM_VERSION && c.pool != [0u8; 32] && c.market != [0u8; 32] && c._reserved == [0u8; 12]
}

/// What tag 123 may do with the claim account of the pool it is about to pin: `None` = the account is empty
/// (create it), `Some(true)` = this market already holds it, `Some(false)` = ANOTHER market holds it (refuse).
pub fn pool_claim_held_by(c: &PoolClaimV22, market: &[u8; 32]) -> bool {
    c.market == *market
}

#[cfg(test)]
mod pool_claim_tests {
    use super::*;
    #[test]
    fn pool_claim_layout_and_validation() {
        let mut c: PoolClaimV22 = bytemuck::Zeroable::zeroed();
        assert!(!validate_pool_claim(&c));
        c.pool = [1; 32];
        c.market = [2; 32];
        c.version = POOL_CLAIM_VERSION;
        assert!(validate_pool_claim(&c));
        assert!(pool_claim_held_by(&c, &[2; 32]) && !pool_claim_held_by(&c, &[3; 32]));
        c._reserved[0] = 1;
        assert!(!validate_pool_claim(&c));
    }
}
