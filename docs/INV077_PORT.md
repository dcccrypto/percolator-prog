# INV-077 port (Toly upstream), by hand

Upstream (aeyakovenko/percolator-prog, read-only): `b7990033` (prod fix), `ea212394`, `7b110913`,
`eb273e3c` (tests), `bbb865f2` (engine pin bump, NOT taken).

## What is ported
`b7990033` src/v16_program.rs, with upstream's names:
- constants `WRAPPER_SOURCE_LIEN_REFRESH_LEG_WEIGHT = 6`, `WRAPPER_MAX_SOURCE_LIEN_REFRESH_WORK = 72`
- `source_lien_refresh_work_view`, `ensure_source_lien_refresh_work_within_wrapper_bound`
- the before-snapshot and the after-check for both portfolios, on the single trade path and the
  batch trade path (placed after the engine call, next to the existing source-domain bound).

## Differences from upstream (and why)
1. **Leg cap.** Ours is `WRAPPER_MAX_PORTFOLIO_ASSETS = 4` (S10-X1); upstream's is 14. With 72/6 kept,
   the worst case here is `8 liened domains + 6 * 4 legs = 32 <= 72`, so the check can never refuse
   a trade in this fork today. It is defence in depth that starts to bite only if the leg cap is raised
   (the check engages from 9 legs with 18+ liens; see the unit test that pins this).
   Upstream's constants were not rescaled, as asked.
2. **Source-domain bound.** Ours is `WRAPPER_MAX_BOUNDED_SOURCE_DOMAINS = 2 * 4 = 8`, upstream's is 28.
3. **Fixtures/tests.** Upstream's INV-077 files (`tests/invariants/cu/inv_077_*.rs`, 14-leg/28-domain
   fixtures, `tests/invariants/README.md` entries) do not exist in this fork at all (no INV-077 base
   `ac719dff` ancestry, no 14-leg fixtures) and cannot be built at cap 4. Not ported as files.
   Instead the bound is tested in-crate (`src/v16_program.rs` `tests`), see below.
4. **`tests/v16_cu.rs` seeded-lien fixture change** (retain 11 of 14 legs): not applicable at cap 4.
5. **Engine.** `bbb865f2` / `eb273e3c` need engine `a55aceb3` (a Resolved close settles at most two
   legs per call). Our engine pin stays `dcccrypto db019142`. The five Resolved-close tests of
   `eb273e3c` are **blocked on the engine**; nothing ported. `ea212394`'s lapsed-domain test needs the
   14-leg fixture and is not buildable here either.
