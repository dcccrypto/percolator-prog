# v2.2 band markets: SDK defaults and product copy

Audience: percolator-sdk (launch wizard, instruction builders) and the app. Source: security
re-review of Wave B (N-1, N-5 and the E-L2 info note), 2026-10-06.

## Defaults the SDK must send (the program only enforces floors)

| InitMarketV22 band field | Program floor (refused below, Custom 105) | SDK default | Why |
|---|---|---|---|
| `band_bps` (d) | 1..=2000, Band Safety Law | 130 (per the design table) | |
| `band_max_epoch_slots` (E) | >= 150 | **600** (~4 min) | A small E pins the book on one missed sweep. |
| `band_max_pin_slots` (Pmax) | >= 8E | **9,000** (~60 min) | `BandPinExpired` (forced recovery at `P_last`) opens after a keeper outage of about E + Pmax slots with a pending target gap: ~64 min at the defaults, ~9 min at the floors. |
| `band_min_leg_notional` (atoms) | >= 10 whole collateral tokens | **100 whole tokens** | Every slot-holding leg locks margin; filling the 256-per-side cap then costs real capital. |
| genesis price | >= 100x the smallest anchor with a 32-tick band (`band_min_wide_anchor(d) * 100`) | quote in lots so the price is well above it | Below the floor re-anchoring stops; 100x means it needs a >99% collapse. |

The wizard should display: "Forced recovery after N minutes of keeper absence" with
`N = (E + Pmax) * 0.4 s / 60`, and "Minimum position size: X" from `band_min_leg_notional`.

## New refusals to explain in the app

| Code | When | Copy (one calm line) |
|---|---|---|
| 104 `PriceBandPinned` | Closing on the favourable side while the mark is still catching up to the oracle (any lag on a band market, not only a pin) | "Price catching up; closing resumes in a few seconds." |
| 111 `PriceBandPositionCap` | The side already holds 256 positions | "This market is full on this side; try again shortly." |
| 112 `PriceBandTooNarrow` | New exposure on an asset whose price fell to the band floor | "This market is close-only at this price." |
| 113 `PriceBandLegBelowMinNotional` | A trade would leave a position below the market minimum | "Below the minimum position size: trade at least X, or close fully." |
| 21 `EngineLockActive` | Earn / insurance / conversion paths while the mark lags | "Price catching up; try again in a few seconds." |

Tag 118 `SweepBandDustLeg { asset_index }` (permissionless; accounts `[caller][market w][portfolio w][bound vault LP portfolio w]`) closes a band leg whose notional at the current mark is below HALF the market minimum, bilaterally against the bound vault LP at the current mark, with no fee. `A` is unchanged, so the market stays open. The app should warn a user whose position falls below half the minimum that it can be closed by anyone.

**Keeper note:** keep the tag-118 sweep OFF on any live market whose deployed wrapper predates this fix (round-2 re-review N-6): the first version used a unilateral reduce, which scales the opposite side's `A` and pushes the asset close-only. Only enable it against a deployment that carries the bilateral sweep (accounts length 4).

Tag 119 `EvictAndTradeCpi` (accounts `[victim portfolio w]` + the usual TradeCpi accounts; data `[119]` + the TradeCpi body): evicts a SMALL leg from a full side. When the side a taker wants to open on is FULL (256 legs) the SDK should retry the open as tag 119, naming a leg on that side that is (a) at most 4x the market's minimum position size and (b) at most half the taker's own size (an indexer query; pick the smallest such leg). It is the caller's choice among eligible legs, not provably the smallest. The evicted leg is closed at the mark with no fee and the taker's fill follows atomically; if the fill fails nothing is evicted. A position above 4x the minimum can never be evicted. Copy for the evicted user: "Your position was closed at the market price because this side was full and a larger position took the slot. Nothing else was charged." The app should tell users of small positions (at or below 4x the minimum) that this can happen on a full market.

The bound vault LP is the one counterparty exempt from the position cap and the minimum leg size (its position is the net of its takers).

## The fast-crash behaviour (E-L2 trade-off)

On a band market the favourable-side close is refused whenever the mark lags the oracle. In a
fast crash with a 4 bps/slot cap, longs cannot exit at the stale (higher) mark until the
staircase catches up, and a long that falls below maintenance on the walking price is
liquidated first. This removes the free option against the LP that v2.1 had, but it moves the
cost of a crash onto users who would previously have exited at the stale mark. The app should
show the catch-up state (target vs current mark) and the copy above; keeper cadence now
matters for UX (sweep every positioned portfolio each epoch, liquidation-pending first).

At the floor (re-anchoring impossible, or the cap law moving 0 ticks) the refusal is lifted:
positions can exit at the current mark, the same price a forced recovery would settle at.
