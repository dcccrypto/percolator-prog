# v2.2 Phase 4 Wave A: wire and account changes (SDK / keeper / app notes)

Branch `feat/v22-wave-a`. Design: `percolator-ops/ledger/phase4-design-2026-10-05.md` items 7
and 8. Allocations: `percolator-ops/ledger/v22-allocations.md`. **No new instruction tags.** All
legacy wires decode exactly as before.

## Errors (explicit discriminants, pinned by `const` asserts)

| code | name | when | suggested copy |
|---|---|---|---|
| 117 | `RedemptionBelowMinPayout` | tag 77 would pay less than `max(wire min, stored min)` | "The exit price moved below your minimum; retry or lower it" |
| 118 | `ExitRequiresLossCurrent` | Live non-bound tag 77 on a book with stale positions or a pending domain loss barrier (after the inline refresh) | "Refreshing positions before your exit; retry shortly" |
| 119 | `LotConfigInvalid` | `lot_exp > 15`, a lot on Hybrid/EWMA, or a growth market (re-)anchored below 10^7 e6 | — (creator tooling) |

117 and 118 leave every account unchanged (the transaction reverts; shares stay escrowed).

## Item 7: lot pricing

**Profile byte +19 = `lot_exp`** (asset oracle profile, `AssetOracleProfileV16::_padding0[0]`).
The market's base unit is a LOT of `10^lot_exp` tokens. Every mark (`mark_e6`, effective price,
`initial_price`) is **per lot**; every position `q` is **in lots** (`POS_SCALE` per lot). The engine
and matcher are unit-agnostic; nothing on chain converts.

**InitMarket (tag 0) wire.** Unchanged legacy (218-byte body) and growth (+4: `r_gap_bps u16,
l_launch_x100 u16`) forms. NEW lot form: growth block + `lot_exp u8` (+5 bytes), `lot_exp` in
`1..=15` (0 in the 5-byte form is refused; send the 4-byte form). Wave B's band trailer, when it
lands, follows `lot_exp`.

**Precision floor.** Every growth market must open at `initial_price >= 10_000_000` (=$10 per lot);
the same floor binds ConfigureAuthMark (tag 62) and RestartAssetOracle on growth assets. Choose
`lot_exp` so the per-lot price at launch is in [$10, $10,000]:
`lot_exp = clamp(ceil(log10(10 / P_token_usd)), 0, 15)`.

**Immutability.** `lot_exp` is written once at InitMarket and carried through every oracle
reconfiguration; ConfigureHybridOracle / ConfigureEwmaMark on a `lot_exp != 0` asset fail with 119.

**SDK helpers** (all formatting must go through one helper):
- `lotExp(market)`: profile byte +19 of asset 0 (`read_asset_oracle_profile`).
- `displayPrice = mark_e6 / 1e6 / 10^lotExp` (per token).
- `sizeTokens = q / POS_SCALE * 10^lotExp`.
- Order entry: tokens → lots, rounding toward zero; show the remainder.
- Keeper: `mark_e6 = round(P_token_e18 * 10^lot_exp / 10^12)` from exact pool reserves (rational, not float). A wrong exponent is a 10^k price error.
- Indexer / charts: store the per-lot mark and `lot_exp`; candles in per-token price.
- App: sizes in tokens; a "1 lot = 10^k TOKEN" tooltip only when the size is not a lot multiple.

## Item 8: R3-M1 exit fix

**Profile byte +20 = `p4_flags`**; bit2 = `EXIT_REQUIRES_LOSS_CURRENT`. Set on every profile a v2.2
program creates; forced on in mainnet builds. Bits 0/1 are reserved for items 6/4 and refused today.

**Tag 76 RequestRedeemLpShares.**
- Legacy: `[76, shares u128]` (17 B) → request account body 96 B (unchanged).
- v2.2: `[76, shares u128, min_payout_atoms u64, keeper_ok u8]` (26 B); `keeper_ok ∈ {0,1}`; the
  all-zero trailer is refused (send legacy). The request PDA is created **16 bytes longer**
  (`HEADER_LEN + 112`) with `LpRedemptionExtV22 { min_payout_atoms u64 @96, keeper_ok u8 @104,
  _reserved [u8;7] @105 }` (body offsets). Any `getProgramAccounts` filter on the request's
  `dataSize` must accept both lengths.

**Tag 77 ExecuteRedemption.**
- Legacy: `[77, domain u16]` (3 B).
- v2.2: `[77, domain u16, min_payout_atoms u64, n_refresh u8]` (12 B); `n_refresh <= 8`; the
  all-zero trailer is refused.
- Accounts: unchanged [0..12]; then `n_refresh` stale positioned portfolios (writable) at
  [13..13+n]; then the vault asset's oracle accounts (none for AuthMark). Refresh is non-bound Live
  only (bound vaults keep [13]/[14] for the vault-LP tail).
- Rules: payout `>= max(wire min, stored min)` else 117; on a Live non-bound vault with bit2 (all
  v2.2 markets), after the inline refresh the asset must have zero stale portfolios and zero domain
  loss barriers, else 118; the redeemer signs [12], **unless** the request stored `keeper_ok = 1`, in
  which case anyone may execute (always loss-gated, always at the stored floor).

**SDK `quoteRedemption()`** must simulate the refreshes: collect every positioned portfolio on the
vault's asset with `stale` (or simply every positioned one), build the 77 with them as [13..]
(address lookup table), simulate, read the payout, and set `min_payout = payout * (1 - tol)`. If the
asset has more than 8 positioned portfolios that are stale after the latest accrual, either wait for
the keeper sweep or use `keeper_ok`. **CU:** 8 single-leg refreshes + the redemption measured
967,557 CU; size `n_refresh` by simulation (a refresh that liquidates costs more).

**App:** "You'll receive at least $X" (the signed floor). The two-step flow sends 76 (v2.2 form
with the floor) then 77 (v2.2 form with the refresh accounts and the floor).

**Keeper:** after a full sweep (book loss-current), execute pending `keeper_ok` requests with an
unsigned 77 (n_refresh 0, wire min 1). Keep the par − E3 gap monitor as telemetry.
