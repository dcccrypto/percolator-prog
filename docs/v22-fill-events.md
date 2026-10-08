# v2.2 wrapper events: executed fills, reductions, value moves

Audience: the SDK and indexer builders. Source of truth for the encoding is
`src/fill_events_v22.rs`; the reference decoder used by the tests is
`tests/support/fill_events.rs` (written independently, from this document). Indexer builders:
read "Trust model and the attribution rule" and "Rules an indexer must follow" before anything
else; the first published attribution rule was forgeable (security review 2026-10-07, M-1).

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
| 1 | 1 | `version`: 1. Layout changes bump it. `kind` and `version` are bytes 0 and 1 in every version. **A decoder skips a kind or a version it does not know** (and a known kind whose length does not match): it must not fail, and must not guess at the fields |
| 2 | 1 | `ix_tag`: the wrapper instruction tag of the **handler** that emitted the event. It can differ from the tag of the outer instruction in the transaction: the trade inside tag 119 reports 10, and a liquidation performed by the pre-crank inside tag 77 (`ExecuteRedemption`) reports 5. Match events to instructions by position in the log, not by this byte |
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
| 11 | 16 | `requested_q` i128: the size the signer asked for (wire size, before any headroom clip). Positive = `taker` long. **Caller-supplied**: it is copied from the instruction data and says nothing about what happened |
| 27 | 16 | `executed_q` i128: the size that executed; 0 on a zero fill. Same sign convention |
| 43 | 8 | `price_e6` u64: the price the position was **booked** at (the asset's `effective_price`). On a zero fill: the reference price only, nothing was booked |
| 51 | 8 | `quoted_price_e6` u64: the matcher's quoted `exec_price` (TradeCpi/BatchTradeCpi) or the wire `exec_price` (TradeNoCpi/BatchTradeNoCpi). It is NOT what the position was booked at. 0 when no matcher answered. **Supplied by the matcher (an LP-chosen program) or by the caller**: informational only, never a price for volume, PnL or charts |
| 59 | 8 | `fee_atoms` u64: the **total** engine trade fee charged on this fill across BOTH portfolios, saturating at `u64::MAX`. See "What `fee_atoms` is" below: it is not "the taker's fee" and it is not protocol revenue |
| 67 | 8 | `backing_fee_atoms` u64: backing-domain fee charged on top (single trades only; 0 in batches) |

`flags`: bit 0 (1) `CLIPPED`: the request was clipped to the LP's headroom before the matcher was
called. bit 1 (2) `PARTIAL`: the matcher filled less than it was asked to (and not zero). bit 2 (4)
`ZERO`: nothing executed. bit 3 (8) `MATCHER`: routed through an external matcher (clear on NoCpi).
`CLIPPED` and `PARTIAL` are independent (the wrapper clips, then the matcher may fill short of the
clipped size). Combinations that occur:

| flags | value | meaning |
|---|---|---|
| `0` | 0x00 | NoCpi fill |
| `MATCHER` | 0x08 | full fill through a matcher |
| `CLIPPED\|MATCHER` | 0x09 | clipped to headroom, the matcher filled the clipped size |
| `PARTIAL\|MATCHER` | 0x0A | not clipped, the matcher filled short |
| `CLIPPED\|PARTIAL\|MATCHER` | 0x0B | clipped to headroom AND the matcher filled short of the clipped size |
| `ZERO\|MATCHER` | 0x0C | not clipped, the matcher returned 0 (`quoted_price_e6` is its quote) |
| `CLIPPED\|ZERO\|MATCHER` | 0x0D | **two cases**: clipped to zero, no matcher call (`quoted_price_e6 == 0`); or clipped to a non-zero size and the matcher returned 0 (`quoted_price_e6 != 0`). `quoted_price_e6` is the only thing that tells them apart |

A decoder must not reject a flag combination or a flag bit it does not know.

### What `fee_atoms` is

`fee_atoms = fee_a + fee_b`: everything the engine charged as trade fee on this fill, summed over
the two portfolios.

* **It is not only the taker's.** When the taker cannot pay the whole fee (no capital, or its fee
  is waived because its PnL is negative) the engine charges the remainder to the maker (the LP):
  the maker-fallback route. Part or all of `fee_atoms` was then paid by `lp`, not by `taker`. The
  event does not say how the sum divides; the two portfolios' capital changes do.
* **It is not protocol revenue.** On `TradeCpi` it includes any LP-requested fee (the P2 fee
  channel: an extra fee the matcher asks for, charged to the taker and credited to the LP). That
  part does not go through the protocol's four-way fee split, so revenue computed from `fee_atoms`
  over-counts. The event does not carry the LP-requested part separately (a version 2 record
  would).
* **It excludes** the maintenance fee, holding rent, and the backing-domain fee
  (`backing_fee_atoms`, its own field).

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

**The unit of `signed_reduced_q` depends on `reason`.** Reason 1 is in **basis** units (the leg's
stored `basis_pos_q`, before ADL scaling). Reasons 2 and 3 are **ADL-effective** units (basis x A /
a_basis). Reasons 4 and 5 are the size traded against the vault LP (the leg's signed position as
the trade path reads it). On a side that has never been ADL-scaled the two units coincide; after
an ADL they do not, so do not add reason-1 sizes to reason-2/3 sizes without converting.

| `reason` | meaning | `ix_tag` | notes |
|---|---|---|---|
| 1 | `REBALANCE_REDUCE` | 44 | **basis units.** The **executed** size: min(requested, unilateral close capacity, position). Unilateral (zero counterparty). Best effort: not emitted if the leg's side cannot be read |
| 2 | `ADL_WIND_DOWN` | 104 | **ADL-effective units** (not the raw basis). Unilateral. Not emitted on the call that only arms the episode. Best effort, as reason 1 |
| 3 | `LIQUIDATION` | 5 (the crank handler that liquidated; also when that crank runs as the pre-crank inside tag 77) | **ADL-effective units.** The change of the position on the liquidated asset across the call. Unilateral. An after-leg that is **absent** is a full close; an after-leg that is present but **unreadable** (a generation or ADL epoch the reader cannot interpret) suppresses the event rather than being read as zero. Not emitted either when the before-leg is unreadable or the change is zero (best effort: an event never makes a liquidation fail) |
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
| 2 `G9` | 111 | insurance backstop draw (mode 0: insurance -> vault LP capital) or capital-only restore (mode 1: vault LP capital -> insurance) | amount moved | backstop receivable outstanding after | mode: 0 draw, 1 restore. Never 3 |
| 3 `RENT_ROUTED` | 106 | unrouted holding rent credited to the bound vault LP by this call (an internal re-labelling, no token moves); not emitted when 0 | atoms routed | 0 | 0 |
| 4 `G9_RESTORE_PNL` | 111 | insurance backstop restore, mode 3: repaid from the vault LP's released profit first, from its capital for the remainder | atoms from released profit | atoms from capital | backstop receivable outstanding after |

For `EARN_EXIT`, `a + b` equals the vault -> redeemer token transfer; `a` is also the fall of the
backing ledger's principal. A G9 PROPOSE (mode 2) moves nothing and emits nothing.

Tag 111 has two restore modes and each has its own sub, so the meaning of `a`/`b`/`c` never depends
on a mode byte inside another sub. Mode 1 (capital only) is `G9` with `c = 1`. Mode 3 (released
profit first) is **always** `G9_RESTORE_PNL`, also when the profit part is 0 (the engine's profit
path was closed and the whole repayment came from capital): the amount repaid into insurance is
`a + b`, the vault LP's capital fell by `b`, its PnL by `a`. A decoder that does not know a `sub`
skips the event.

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
| liquidation (crank, tag 5; also the pre-crank inside 77, still reported as tag 5) | A | REDUCE reason 3. Liquidation **fee, insurance used, residual booked** are NOT logged (C): the engine drops them on the crank path and deriving them needs the engine's `LiquidationOutcomeV16`; an engine change is out of scope. They remain visible as the portfolio / insurance account diff |
| engine ADL scaling of other accounts | B | no per-account amount exists; the market account's `a_long` / `a_short` and epochs are the state. Effective size = basis x A / a_basis |
| 106 SettleHoldingRent | A | MOVE `RENT_ROUTED` (routed amount). Rent *charged* to a portfolio during any settle is C: it is inside engine settlement; the instruction's own portfolio capital diff shows it |
| 77 ExecuteRedemption | A | MOVE `EARN_EXIT` (the split). Paid total and shares burned are also B (SPL transfer and burn) |
| 111 InsuranceBackstopDraw | A | MOVE `G9` (modes 0, 1) or `G9_RESTORE_PNL` (mode 3) |
| 78 LpVaultCrankFees | C | amounts split across counters inside `handle_lp_vault_crank_fees`, whose stack frame is 3,968 B of 4,096 and pinned at that size by the frame gate; an emit there needs that function refactored first. The split is visible as the market account counter diff |
| 108 BondDeposit, 109 BondRequestWithdraw, 110 BondExecuteWithdraw | B / C | deposit and payout amounts are token transfers (B). Shares minted/burned live only in the `BondPositionV20` account (state diff, not a log): C, to be added if the indexer cannot diff that account |
| 112 RescueDeposit | B | the deposit is a token transfer, the shares minted an SPL mint; priced from state the market account already shows |
| everything else | B | their amounts are on the wire or in token balances |

Also not logged, by design: the realised PnL of a fill (visible in the account diff), the split of
the fee between taker and maker fallback (only the sum is known per leg in a batch), funding and
maintenance-fee settlement, and any per-account effect of an ADL step.

## Trust model and the attribution rule (read this before indexing)

1. **Only trust successful transactions.** The logs of a failed transaction are still visible, and
   they can hold a complete, well-formed wrapper event for something that never happened: a
   transaction whose first instruction is a trade and whose second instruction fails logs the
   trade's FILL and then reverts everything (`fill_events_only_trusted_on_success` builds exactly
   this). Solana has no way for a program to recover from an error inside the same transaction, so
   in a *successful* transaction every event describes state that is final. An indexer must ignore
   every event of a failed transaction (`meta.err != null`). Handlers additionally emit as late as
   they can (after the state change and the post-fill gates).
2. **Attribute a `Program data:` line to the wrapper only by the runtime's own frame lines.**
   Other programs run inside a wrapper transaction (the matcher is chosen by the LP) and can print
   anything through `msg!` and `sol_log_data`. What they cannot do is print a line that does not
   start with `Program log: ` or `Program data: `. So:

   * Treat each element of `logMessages` as **one atomic line**. Never join the array and split it
     again on newlines: one `msg!` can contain newlines, and after a re-split its text becomes
     lines of its own.
   * Keep a stack of program ids. **Push** only on a line that matches, in full,
     `^Program <base58 pubkey> invoke \[(\d+)\]$` where the id decodes to exactly 32 bytes and the
     depth equals the current stack length + 1.
   * **Pop** only on a line that is exactly `Program <id on top of the stack> success`, or that
     starts with `Program <id on top of the stack> failed: `.
   * A line that starts with `Program data: ` belongs to the program on **top of the stack at that
     line**. Accept it only when that id is the wrapper's program id, pinned in your configuration
     (not read from the transaction).
   * **Any inconsistency makes the whole transaction's events unknown** (not "no events"): an
     invoke at the wrong depth, a `success` / `failed: ` for an id that is not on top of the stack,
     a `Program data: ` line with an empty stack, a log that ends with a frame still open.

   Why it has to be this strict: the first version of this rule popped on any line ending in
   `success` and pushed on anything starting `invoke [`. A matcher that did
   `msg!("success"); sol_log_data(forged)` produced `Program log: success`, which that walker read
   as the matcher returning, so the forged line landed in the wrapper's frame; a further
   `msg!("invoke [2]")` kept the stack balanced. One transaction, any LP with its own matcher, a
   forged FILL / REDUCE / MOVE naming any market, taker, size and price. Under the rule above
   `log:` is not a program id, so those lines move nothing. The wrapper may itself be called by
   CPI: its lines are still inside its own frame. The reference implementation is
   `wrapper_frame_tokens` / `tx_events` in `tests/support/fill_events.rs`; the forgeries, the
   embedded-newline case and every inconsistency are regression tests in
   `tests/v22_fill_events_attribution.rs`.
3. **Not every field is the wrapper's own statement.** Computed by the wrapper from its own state
   and safe to use: `kind`, `version`, `ix_tag`, `market`, the portfolio keys, `asset_index`,
   `asset_gen`, `flags`, `executed_q`, `price_e6`, `fee_atoms`, `backing_fee_atoms`, every REDUCE
   and MOVE field. **Copied from untrusted input**: `requested_q` (instruction data, on every
   route) and `quoted_price_e6` (the matcher's return on the CPI routes, instruction data on the
   NoCpi routes). Use those two for display and diagnostics only. The event carries the `market`,
   so it is never ambiguous about which market it is for; check that market against your registry
   and `asset_gen` against the asset's current generation before accepting the event.
4. **Nothing leaks that is not already public.** Pubkeys are the instruction's own accounts; the
   rest are sizes, prices and fees that the same transaction moves in public account data.
5. **Log truncation can remove an event from a successful transaction.** The runtime's log
   collector has a 10,000-byte budget per transaction (validator default). A line that would cross
   it is dropped, the single element `Log truncated` is inserted once, and **shorter lines after
   it are still accepted**. The events are emitted last, so a transaction whose earlier lines used
   the budget loses the event line while the short `Program <id> success` lines survive: the
   frames look complete and the event is simply not there. Any program in the transaction (the
   matcher) or the transaction's author (extra instructions that log) can cause this on purpose.
   The wrapper's own heaviest case (11-leg `BatchTradeCpi`) logs 3,935 B in total, 1,251 B of it
   the event line (`v16_cu` prints the figure and asserts < 10,000).

   **Truncation fallback.** If the element `Log truncated` appears anywhere in `logMessages`, or
   `logMessages` is null or empty (some RPC nodes do not keep logs), the transaction's events are
   **unknown**. Never record "no fill". For each wrapper instruction in the transaction, re-read
   the taker's and the LP's portfolio accounts (the legs before and after, from the transaction's
   pre/post state if your source has it, otherwise from the previous and current indexed state) and
   record a **derived** fill: size = the change of the taker's position on the asset, with price
   and fee marked unknown. Flag derived rows so they can be told apart from decoded ones.
6. **Multi-event order.** Within one instruction events appear in execution order (tag 119: the
   REDUCE of the victim, then the FILL). Across instructions, use the instruction order of the
   transaction.
7. **Events can be missing without truncation.** The liquidation (reason 3), tag 44 and tag 104
   REDUCE events are best effort: they are skipped when the wrapper cannot read the leg it needs,
   because an event must never make the instruction fail. Reconcile positions against account
   state periodically.

## Rules an indexer must follow

1. Process successful transactions only (`meta.err == null`).
2. `Log truncated` anywhere, or null / empty `logMessages`: the events are unknown. Reconcile from
   portfolio state (truncation fallback above). Never "no fill".
3. Each `logMessages` element is atomic. Apply the strict frame rule (item 2 above); any
   inconsistency marks the whole transaction unknown.
4. Accept a `Program data:` token only when the top of the stack is the pinned wrapper program id
   and the event's `market` is in your registry with a matching `asset_gen`.
5. Skip unknown kinds, versions, MOVE subs and REDUCE reasons. Never fail on them.
6. Volume is `executed_q` (at `price_e6`) only. Never `requested_q`, never `quoted_price_e6`.
7. `fee_atoms` is the total across taker and maker, including any LP-requested fee. It excludes the
   maintenance fee, rent and the backing fee. It is neither "the taker's fee" nor revenue.
8. The event's `ix_tag` can differ from the outer instruction's tag (10 inside 119, 5 inside 77).
9. REDUCE units differ by reason (1 basis; 2 and 3 ADL-effective).
10. A liquidation / tag 44 / tag 104 event can be missing (best effort). Reconcile positions
    periodically.

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
// Attribution: logs = meta.logMessages (string[]), used element by element. Returns the wrapper's
// base64 tokens, or null when the events are unknown.
const INVOKE = /^Program ([1-9A-HJ-NP-Za-km-z]{32,44}) invoke \[(\d+)\]$/;
function wrapperTokens(logs: string[] | null, wrapper: string): string[] | null {
  if (!logs || logs.length === 0 || logs.includes("Log truncated")) return null;
  const stack: string[] = [], out: string[] = [];
  for (const line of logs) {
    const m = INVOKE.exec(line);
    if (m && isPubkey(m[1])) {                 // isPubkey: base58-decodes to exactly 32 bytes
      if (Number(m[2]) !== stack.length + 1) return null;
      stack.push(m[1]);
      continue;
    }
    const r = /^Program ([1-9A-HJ-NP-Za-km-z]{32,44}) (success$|failed: )/.exec(line);
    if (r && isPubkey(r[1])) {
      if (stack[stack.length - 1] !== r[1]) return null;
      stack.pop();
      continue;
    }
    if (line.startsWith("Program data: ")) {
      if (stack.length === 0) return null;
      if (stack[stack.length - 1] === wrapper) out.push(...line.slice(14).split(" ").filter(Boolean));
    }
  }
  return stack.length === 0 ? out : null;
}

const b = Buffer.from(token, "base64");
if (b.length < 35 || b[1] !== 1) return;        // unknown version (or junk): skip, do not throw
const kind = b[0], ixTag = b[2];
const market = new PublicKey(b.subarray(3, 35));
if (kind === 1 && b.length >= 100 && b.length === 100 + 75 * b[99]) {
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
}                                               // kind 2: length 134; kind 3: length 62; else skip
```

## Tests

`tests/v22_fill_events.rs` (TradeCpi full / clipped / zero / matcher-partial / matcher-zero /
clipped-then-partial / short, quoted price != booked price on TradeCpi and on a batch, the fee of a
short taker and of the maker-fallback route, TradeNoCpi, BatchTradeCpi, RebalanceReduce incl.
capacity- and position-clipped, a failed transaction whose log carries a fill that did not happen),
`tests/v22_fill_events_attribution.rs` (the attribution rule on synthetic logs: forged
`Program log: success` / `invoke [2]`, embedded newlines, `Log truncated`, null logs, frame
inconsistencies, unknown kind / version; no `.so` needed),
`tests/v16_cu.rs` (11-leg packed batch, 1-leg and 14-leg liquidation crank), `tests/v22_band_rent.rs`
(118, 119, 106), `tests/p2b_adl_wind_down.rs` (104), `tests/earn_drain_replay.rs` and
`tests/v16_fork_lp_vault_redeem.rs` (77; the second checks each part of the split against the
ledger), `tests/p4_wave_d.rs` (111 draw, restore, and the mode-3 restore sub). The unit tests in
`src/fill_events_v22.rs` pin the lengths, the worked examples and the liquidation absent /
unreadable decision. Each LiteSVM test decodes the events from the transaction logs of the built
`.so` and compares them with the account-state change.
