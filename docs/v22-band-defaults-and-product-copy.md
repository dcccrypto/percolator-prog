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
