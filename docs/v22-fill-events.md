# v2.2 wrapper events: executed fills, reductions, value moves

Audience: the SDK and indexer builders. Source of truth for the encoding is
`src/fill_events_v22.rs`; the reference decoder used by the tests is
`tests/support/fill_events.rs` (written independently, from this document).

## Why

Before this change nothing in a transaction said what a trade did. The wire of `TradeCpi` (tag 10)
carries the *requested* size and the taker's fee *cap*; the wrapper clips the size to the LP's
headroom (a clip to zero returns `Ok` with no matcher call), asks the matcher, books the matcher's
`exec_size` at the asset's `effective_price`, and charges a fee computed on chain. None of the
executed size, booked price or charged fee was in any log, and the matcher's answer lives only in
its context account, which the next trade overwrites. `RebalanceReduce` (tag 44) discarded the
engine's `reduced_q`. Return data is clobbered by any later CPI and is absent from the RPC views
indexers use.

## Transport

* Each event is **one `sol_log_data` call with ONE slice**, so one log line
  `Program data: <base64>` with exactly one token. Decoders may still split on spaces.
* All integers are little-endian. `i128` is two's complement, 16 bytes. Pubkeys are the raw 32
  bytes (base58 them yourself). Sizes (`*_q`) are engine position units (`POS_SCALE` = 1,000,000
  per unit). Prices are e6 per unit (`price_e6`). Fees are collateral atoms.
* There is no account layout change, no new instruction and no new error code in this feature.

## Header (every event, 35 bytes)

| off | len | field |
|---|---|---|
| 0 | 1 | `kind`: 1 FILL, 2 REDUCE, 3 MOVE |
| 1 | 1 | `version`: 1. A decoder must refuse a version it does not know. Layout changes bump it. |
| 2 | 1 | `ix_tag`: the wrapper instruction tag of the handler that emitted the event (see per-event notes; for the trade inside tag 119 it is 10) |
| 3 | 32 | `market` account pubkey |

## FILL (kind 1)

One line per instruction (per up to 11 legs: a batch longer than 11 legs, which the wrapper does
not currently accept, would split into several lines in leg order).

| off | len | field |
|---|---|---|
| 35 | 32 | `taker` portfolio: `account_a`, the fee payer and, on a matcher route, the signing taker |
| 67 | 32 | `lp` portfolio: `account_b`, the counterparty (the LP on a matcher route) |
| 99 | 1 | `n`: number of records in this line |
| 100 + 75 i | 75 | record i |

Record (75 bytes, offsets relative to the record):

| off | len | field |
|---|---|---|
| 0 | 2 | `asset_index` u16 |
| 2 | 8 | `asset_gen` u64: the asset's `market_id` (generation), so a reused asset index is unambiguous |
| 10 | 1 | `flags`, below |
| 11 | 16 | `requested_q` i128: the size the signer asked for (wire size, before any headroom clip). Positive = `taker` long |
| 27 | 16 | `executed_q` i128: the size that executed; 0 on a zero fill. Same sign convention |
| 43 | 8 | `price_e6` u64: the price the position was **booked** at (the asset's `effective_price`). On a zero fill: the reference price only, nothing was booked |
| 51 | 8 | `quoted_price_e6` u64: the matcher's quoted `exec_price` (TradeCpi/BatchTradeCpi) or the wire `exec_price` (TradeNoCpi/BatchTradeNoCpi). It is NOT what the position was booked at. 0 when no matcher answered |
| 59 | 8 | `fee_atoms` u64: engine trade fee actually charged (taker plus the maker fallback share), saturating at `u64::MAX` |
| 67 | 8 | `backing_fee_atoms` u64: backing-domain fee charged on top (single trades only; 0 in batches) |

`flags`: bit 0 (1) `CLIPPED`: the request was clipped to the LP's headroom before the matcher was
called. bit 1 (2) `PARTIAL`: the matcher filled less than it was asked to (and not zero). bit 2 (4)
`ZERO`: nothing executed. bit 3 (8) `MATCHER`: routed through an external matcher (clear on NoCpi).
Combinations that occur: `CLIPPED|ZERO|MATCHER` (clipped to zero, no matcher call, `Ok`),
`ZERO|MATCHER` (the matcher returned 0), `CLIPPED|MATCHER`, `PARTIAL|MATCHER`, `MATCHER`, `0`.

Which instructions emit it, and the tag in the header:

| instruction | `ix_tag` | notes |
|---|---|---|
| `TradeNoCpi` | 6 | one record, flags 0 |
| `TradeCpi` | 10 | one record; a **zero fill is emitted too** (both the headroom-clipped-to-zero exit and the matcher-returned-0 exit), so a zero fill never has to be inferred from the absence of a CPI |
| `BatchTradeNoCpi` | 66 | one line, one record per leg, in leg order |
| `BatchTradeCpi` | 67 | one line, one record per leg, in leg order. A batch is atomic and refuses zero fills, so no record is `ZERO`; a leg the matcher filled short carries `PARTIAL` |
| `EvictAndTradeCpi` | 10 | the taker's trade inside tag 119 is the ordinary TradeCpi handler and reports tag 10; the eviction itself is a REDUCE with tag 119 (below), emitted first |

## REDUCE (kind 2), 134 bytes

| off | len | field |
|---|---|---|
| 35 | 32 | `portfolio` whose position was reduced |
| 67 | 32 | `counterparty` portfolio (the bound vault LP for forced closes); all zero for a unilateral reduction |
| 99 | 2 | `asset_index` u16 |
| 101 | 8 | `asset_gen` u64 |
| 109 | 1 | `reason` |
| 110 | 16 | `signed_reduced_q` i128: the signed change of the portfolio's position. A long being reduced is negative, a short being covered is positive |
| 126 | 8 | `price_e6` u64: the price used (the asset's `effective_price`; `P_last` for forced closes) |

| `reason` | meaning | `ix_tag` | notes |
|---|---|---|---|
| 1 | `REBALANCE_REDUCE` | 44 | the **executed** size: min(requested, unilateral close capacity, position). Unilateral (zero counterparty) |
| 2 | `ADL_WIND_DOWN` | 104 | the ADL-**effective** size closed (not the raw basis). Unilateral. Not emitted on the call that only arms the episode |
| 3 | `LIQUIDATION` | 5 (the permissionless crank that liquidated) | the change of the ADL-effective position on the liquidated asset across the call. Unilateral. Not emitted if the change cannot be derived or is zero (best effort: an event never makes a liquidation fail) |
| 4 | `DUST_SWEEP` | 118 | the whole leg, bilateral against the bound vault LP at `P_last`, no fee |
| 5 | `EVICTION` | 119 | the victim's whole leg, bilateral against the bound vault LP at `P_last`, no fee; emitted before the taker's FILL |

A liquidation that happens inside a trade (`TradeNoCpi` / `TradeCpi` closing a liquidatable
counterparty) is a fill and is reported as a FILL, not a REDUCE.

## MOVE (kind 3), 62 bytes

Value moves whose amount is decided on chain and appears in no instruction data and no token
balance change.

| off | len | field |
|---|---|---|
| 35 | 1 | `sub` |
| 36 | 2 | `asset_index` u16 (`0xFFFF` = none) |
| 38 | 8 | `a` u64 |
| 46 | 8 | `b` u64 |
| 54 | 8 | `c` u64 |

| `sub` | `ix_tag` | meaning | a | b | c |
|---|---|---|---|---|---|
| 1 `EARN_EXIT` | 77 | principal / earnings split of an Earn exit payout and the shares burned | principal atoms | earnings atoms | shares burned |
| 2 `G9` | 111 | insurance backstop draw (mode 0: insurance -> vault LP capital) or restore (mode 1: vault LP capital -> insurance) | amount moved | backstop receivable outstanding after | mode (0 draw, 1 restore) |
| 3 `RENT_ROUTED` | 106 | unrouted holding rent credited to the bound vault LP by this call (an internal re-labelling, no token moves); not emitted when 0 | atoms routed | 0 | 0 |

For `EARN_EXIT`, `a + b` equals the vault -> redeemer token transfer. A G9 PROPOSE (mode 2) moves
nothing and emits nothing. The G9 restore in this build repays from the vault LP's **capital only**
(free = min(capital, certified equity - IM)); there is no PnL component to log.

## Per-instruction classification

A = emitted (above). B = already recoverable from the instruction data, the token balance
changes, or the account diff, so not logged. C = needs an event, deliberately not done here (reason
given).

| instruction | class | what / why |
|---|---|---|
| 10 TradeCpi, 67 BatchTradeCpi | A | FILL. Executed size, booked price, fee and the clip/partial/zero flags are on no other surface |
| 6 TradeNoCpi, 66 BatchTradeNoCpi | A | the wire carries size and `exec_price`, but the booked price (`effective_price`) and the fee are computed on chain, so they are logged; requested == executed |
| 119 EvictAndTradeCpi | A | REDUCE (victim) then FILL (taker) |
| 118 SweepBandDustLeg | A | REDUCE |
| 44 RebalanceReduce | A | REDUCE; the wire has only the request |
| 104 AdlWindDown | A | REDUCE (effective size). 105 (setter) is B: its value is on the wire |
| liquidation (crank, tag 5) | A | REDUCE reason 3. Liquidation **fee, insurance used, residual booked** are NOT logged (C): the engine drops them on the crank path and deriving them needs the engine's `LiquidationOutcomeV16`; an engine change is out of scope. They remain visible as the portfolio / insurance account diff |
| engine ADL scaling of other accounts | B | no per-account amount exists; the market account's `a_long` / `a_short` and epochs are the state. Effective size = basis x A / a_basis |
| 106 SettleHoldingRent | A | MOVE `RENT_ROUTED` (routed amount). Rent *charged* to a portfolio during any settle is C: it is inside engine settlement; the instruction's own portfolio capital diff shows it |
| 77 ExecuteRedemption | A | MOVE `EARN_EXIT` (the split). Paid total and shares burned are also B (SPL transfer and burn) |
| 111 InsuranceBackstopDraw | A | MOVE `G9` |
| 78 LpVaultCrankFees | C | amounts split across counters inside `handle_lp_vault_crank_fees`, whose stack frame is 3,968 B of 4,096 and pinned at that size by the frame gate; an emit there needs that function refactored first. The split is visible as the market account counter diff |
| 108 BondDeposit, 109 BondRequestWithdraw, 110 BondExecuteWithdraw | B / C | deposit and payout amounts are token transfers (B). Shares minted/burned live only in the `BondPositionV20` account (state diff, not a log): C, to be added if the indexer cannot diff that account |
| 112 RescueDeposit | B | the deposit is a token transfer, the shares minted an SPL mint; priced from state the market account already shows |
| everything else | B | their amounts are on the wire or in token balances |

Also not logged, by design: the realised PnL of a fill (visible in the account diff), the split of
the fee between taker and maker fallback (only the sum is known per leg in a batch), funding and
maintenance-fee settlement, and any per-account effect of an ADL step.

## Trust model and the attribution rule (read this before indexing)

1. **Only trust successful transactions.** The logs of a failed transaction are still visible, and
   a handler may have emitted before a later check failed. Solana has no way for a program to
   recover from an error inside the same transaction, so in a *successful* transaction every event
   describes state that is final. An indexer must ignore events of failed transactions. Handlers
   additionally emit as late as they can (after the state change and the post-fill gates).
2. **Attribute a `Program data:` line to the wrapper only by the invoke frames.** Walk the log
   lines keeping a stack: `Program <id> invoke [n]` pushes, `Program <id> success` and
   `Program <id> failed: ...` pop. A `Program data:` line belongs to the program on **top of the
   stack at that line**. Accept it only when that program is the wrapper's program id. Any other
   program can emit the same bytes in its own frame (or around a CPI into the wrapper); they are
   not attributed to the wrapper by this rule. The wrapper may itself be called by CPI: its lines
   are still inside its own frame. The reference implementation is `wrapper_events` in
   `tests/support/fill_events.rs` and is exercised, including a forged-copy case, by
   `attribution_rule_is_frame_based`.
3. The wrapper never embeds caller-supplied bytes in an event: every field is read from wrapper
   state or computed by it. The event carries the `market`, so an event is never ambiguous about
   which market it is for, and `ix_tag` says which handler produced it.
4. **Nothing leaks that is not already public.** Pubkeys are the instruction's own accounts; the
   rest are sizes, prices and fees that the same transaction moves in public account data.
5. **Log truncation.** The runtime truncates a transaction log at 10,000 bytes (validator default).
   The events are emitted last, so a transaction whose earlier logs overflow could lose them. The
   heaviest case (11-leg `BatchTradeCpi`) logs 3,935 B in total, 1,251 B of it the event line
   (`v16_cu` prints the figure and asserts < 10,000). An indexer that sees `Log truncated` must treat
   the transaction's events as unknown and not as "no fill".
6. **Multi-event order.** Within one instruction events appear in execution order (tag 119: the
   REDUCE of the victim, then the FILL). Across instructions, use the instruction order of the
   transaction.

## Compute cost

Measured in LiteSVM against the built `.so` (see the PR for the full table). `sol_log_data` costs
about 100 CU plus one CU per byte; the rest is encoding. A FILL line is 175 B (single trade) and
900-ish bytes for 11 legs, one packed line for the whole batch instead of one per leg.

## Worked examples

All use market `0x01 x32`, taker `0x02 x32`, LP `0x03 x32`; positions in `POS_SCALE` = 1e6 units,
prices e6.

**1. TradeCpi clipped by LP headroom** (asked 15, executed 10; fee 1,000 atoms; booked and quoted
price 100). 175 bytes:

```
AQEKAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAQAABwAAAAAAAAAJwOHkAAAAAAAAAAAAAAAAAICWmAAAAAAAAAAAAAAAAAAA4fUFAAAAAADh9QUAAAAA6AMAAAAAAAAAAAAAAAAAAA==
```

Decoded: `kind 1, version 1, ix_tag 10`, market, taker, lp, `n = 1`, record:
`asset_index 0, asset_gen 7, flags 0x09 (CLIPPED|MATCHER), requested_q +15,000,000,
executed_q +10,000,000, price_e6 100,000,000, quoted_price_e6 100,000,000, fee_atoms 1,000,
backing_fee_atoms 0`.

**2. TradeCpi zero fill (LP at cap; no matcher call).** `flags 0x0D (CLIPPED|ZERO|MATCHER)`,
requested +3,000,000, executed 0, `price_e6` the reference price, quoted 0, fee 0:

```
AQEKAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAQAABwAAAAAAAAANwMYtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4fUFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
```

**3. BatchTradeCpi, two legs** (`ix_tag 67`, `n = 2`; leg 1 filled 0.5 of 2 by the matcher:
`flags 0x0A (PARTIAL|MATCHER)`, booked 250, quoted 249). 250 bytes:

```
AQFDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgAABwAAAAAAAAAIQEIPAAAAAAAAAAAAAAAAAEBCDwAAAAAAAAAAAAAAAAAA4fUFAAAAAADh9QUAAAAAAAAAAAAAAAAAAAAAAAAAAAEACAAAAAAAAAAKgIQeAAAAAAAAAAAAAAAAACChBwAAAAAAAAAAAAAAAACAsuYOAAAAAEBw1w4AAAAAAAAAAAAAAAAAAAAAAAAAAA==
```

**4. RebalanceReduce (tag 44)**: portfolio `0x02 x32`, no counterparty, asset 0 gen 7, reason 1,
`signed_reduced_q -4,000,000` (a long reduced by 4), price 100. 134 bytes:

```
AgEsAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAEA98L/////////////////AOH1BQAAAAA=
```

**5. Earn exit (tag 77)**: `sub 1`, no asset, principal 9,000,000, earnings 1,250,000, shares
burned 10,000,000. 62 bytes:

```
AwFNAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB//9AVIkAAAAAANASEwAAAAAAgJaYAAAAAAA=
```

### Decoding in a few lines (TypeScript sketch)

```ts
const b = Buffer.from(token, "base64");
const kind = b[0], version = b[1], ixTag = b[2];
const market = new PublicKey(b.subarray(3, 35));
if (kind === 1) {
  const taker = new PublicKey(b.subarray(35, 67)), lp = new PublicKey(b.subarray(67, 99));
  for (let i = 0; i < b[99]; i++) {
    const o = 100 + 75 * i;
    const rec = {
      assetIndex: b.readUInt16LE(o), assetGen: b.readBigUInt64LE(o + 2), flags: b[o + 10],
      requestedQ: readI128LE(b, o + 11), executedQ: readI128LE(b, o + 27),
      priceE6: b.readBigUInt64LE(o + 43), quotedPriceE6: b.readBigUInt64LE(o + 51),
      feeAtoms: b.readBigUInt64LE(o + 59), backingFeeAtoms: b.readBigUInt64LE(o + 67),
    };
  }
}
```

## Tests

`tests/v22_fill_events.rs` (TradeCpi full / clipped / zero / matcher-partial / short, TradeNoCpi,
BatchTradeCpi, RebalanceReduce incl. capacity- and position-clipped, frame-attribution),
`tests/v16_cu.rs` (11-leg packed batch, 1-leg and 14-leg liquidation crank), `tests/v22_band_rent.rs`
(118, 119, 106), `tests/p2b_adl_wind_down.rs` (104), `tests/earn_drain_replay.rs` (77),
`tests/p4_wave_d.rs` (111 draw and restore). Each decodes the events from the transaction logs of the
built `.so` and compares them with the account-state change.
