# Upstream percolator-prog, 12-18 Nov 2026: one line per commit

All first-parent commits on upstream `main` dated 12-18 Nov (32 commits, daa0576b .. 9199d869) are listed: 28 as rows below, 4 under
"Not redone here" (9199d869, b7990033, eb273e3c, ea212394). Rows 21-24 were added in the follow-up job after its fresh review found them missing.

Source: `aeyakovenko/percolator-prog` main (read-only `upstream` remote). Nothing was sent upstream.
(The job asked for `docs/upstream-1112-1118/TABLE.md`. This job is tests-only and its pre-push hook refuses
non-test paths, so the table lives under `tests/`.)

"Ours" means the v2.2 engine branch `dcccrypto/percolator` `feat/v22-engine-rc23-2026-10-22` (tip `3e5970f3`;
merged ports #309, #310, #362; drafts #311, #312, #322 are NOT merged). The wrapper's CI builds against
`ENGINE_CI_SIBLING=db019142` (`ci/deployed-refs.env`), which is older than #309/#310/#362, so the ported tests
were run against both.

Our fork carries only two upstream invariant files (`tests/invariants/cu/inv_031_*`, ported in 24ada763). It does
not carry the rest of upstream's invariant suite (`tests/invariants/{cu,stateful,public_sbf}/*`) or its support
harness (`tests/support/fuzz_model.rs` 36k lines, `tests/support/invariant_discovery.rs` 23k lines). Commits that
only re-tune expectations inside those absent files have nothing in our tree to apply to; they are verdict (a)
with the reason "file absent", whatever the engine status.

Verdicts: (a) not applicable; (b) port the test. GREEN/RED: result of the ported test on our base.

| # | Upstream commit | Engine fix it follows | Ours has it? | Verdict |
|---|---|---|---|---|
| 1 | daa0576b (#456) test expectations for the launch fixes | engine #215, #216, #222-#229, #242 (+ prog #451 surplus withdraw in `src/`) | mixed (#228 yes; most of the batch not ported) | (a) touches `src/v16_program.rs` (out of scope, tests-only) and 13 upstream invariant/support files we do not carry |
| 2 | e5bc3e27 (#452/#459) mark `--no-default-features` unsupported | none (Cargo.toml/README) | n/a | (a) build-config note, not a test; our build already requires `--features devnet` (scripts/ci-test.sh) |
| 3 | 0d8f187e pin b22bef7d | b22bef7d = engine #249 (resolved junior backing on provider withdrawals) | no | (a) pin bump; the edits are pin constants in absent census files |
| 4 | 531367eb source-completeness censuses | none (census of upstream instruction surface, tag 70, #170/#386/#451) | n/a | (a) censuses of upstream's own wrapper surface, in 9 absent files |
| 5 | 4acc6d95 DrainOnly forfeit with live OI refused | engine #205 (a2153343) | no (only in draft #311) | (a) edits absent `fuzz_model.rs`/`invariant_discovery.rs`; behaviour our engine lacks |
| 6 | ebe6169e riskiest-leg liquidation, inv_020 | engine #176 (a5e0de73) | yes (#309) | (a) re-tunes 10 absent `inv_020_*` files; no inv_020 suite here |
| 7 | 9b6b2e77 riskiest-leg liquidation, outside inv_020 | engine #176 (a5e0de73) | yes (#309) | (a) re-tunes 4 absent invariant files + absent `invariant_discovery.rs` |
| 8 | 9024b529 backed-gain cure in reset-carry matrix | engine #172 site-2 cure (adf5cb64) | no (#310 took only 137662a9, the SettleB K/F order fix) | (a) behaviour our fork lacks; file absent |
| 9 | 33fafa1a S2 late-debtor and shared-custody worlds | engine #246 S2 (bdaebc3e + 54633dcb) | yes (dc1fa4d9 via #304) | (a) re-tunes absent inv_067/inv_070 files; engine side carries the mirror test (`s2_late_debt_beyond_gap...`) |
| 10 | b42fe017 expectations hidden by pin guards | engine #226 (prog#457 netting) and #228 (prog#450 forfeit funding) | #228 yes (e7a33eb0, fff714db); #226 no (own #457 handling in e7b22061, upstream commits not adopted) | (a) absent inv_028/inv_039 files |
| 11 | ca2aaa11 lien-aware credit rate | engine #250 (c7ae2256, 596b3d98) | no (only in draft #322) | (a) behaviour our fork lacks; also edits `src/` unit fixture |
| 12 | b7e1f4b5 latent-domain backing expiry in Live refresh | engine #243 (ea8cc9c5) | no | (a) behaviour our fork lacks; files absent |
| 13 | 3a05b4b5 loss-domain booking of consumed K/F support | engine #175 (487b49c0) | equivalent own fix (0040bb3a, in db019142) | (a) re-tunes 6 absent inv_024/039/070/073 files |
| 14 | 357157e6 pin a712af76 | a712af76 (#250/#251 docs) | no | (a) pin bump |
| 15 | 72132c9a burned lien's backing to the loss domain | engine 1683b11d (#250 follow-up) | no | (a) behaviour our fork lacks; file absent |
| 16 | 9e4139f3 pin 1683b11d | 1683b11d | no | (a) pin bump |
| 17 | 401f7081 pin 427dc5fc | 427dc5fc (perf, #250 follow-up) | no | (a) pin bump |
| 18 | ac719dff INV-077 liened loss refresh at the source cap | engine 1683b11d (liened-face fix) | no | (a) INV-077 max-shape: 5-6 legs over 28 source domains; vacuous at our 4-leg portfolio cap unless #740 merges. Not ported |
| 19 | 506016b5 INV-031 provider exit capped at principal | engine 827a125f | yes (#362) | (a) already ported: 24ada763 carries this file, adapted to our stricter wrapper gate (E-LSA-W, #470). Checked against #708/#711: no overlap |
| 20 | 731338e0 pin 827a125f | 827a125f | yes (#362) | (a) pin bump |
| 21 | 8b10d3b2 Live value exits wait for unsettled positions on their own asset (INV-031) | prog gate in `src/` (7 lines in `asset_local_loss_stale_view`), no engine commit | yes, own gate: `asset_local_open_kf_cohort_view` in `live_domain_withdraw_health_or_shutdown_view` (E-LSA-W, #470) | (a) already ported: 24ada763 (whose message names 8b10d3b2) carries its `inv_031_live_exit_loss_stale_gate.rs` fixture and, with row 19, the provider-exit file it edits; the `src/` lines are not duplicated |
| 22 | ec03c68d pin 5e3af071 | 5e3af071 (a late resolved loss repays the provider that fronted the gain) | no (not an ancestor of 3e5970f3) | (a) pin bump; edits are pin constants in 29 absent census/invariant files and upstream's own `v16_cu.rs` pin string |
| 23 | 7b110913 INV-077 source-lien refresh bound refuses a batch as a whole | none (test only, against upstream's b7990033 bound) | no (the bound is in our open PR #740, not merged) | (a) edits absent `inv_077_source_lien_loss_refresh.rs`; INV-077 belongs with #740 (b7990033/eb273e3c/ea212394), not redone here |
| 24 | bbb865f2 pin a55aceb3 | a55aceb3 (resolved close settles losses over source claims a bounded number of legs per call) | no (not an ancestor of 3e5970f3) | (a) pin bump; same 29 absent files as ec03c68d |
| 25 | 37849dfc INV-031 payment stranded by a reversal | engine 9a219cca | no | (b) ported into `inv_031_provider_exit_principal.rs`: **GREEN** (2 tests), kept as regression guards. Our fork refuses through its ledger-principal cap (Custom 25), not through 9a219cca |
| 26 | 2d03e07e INV-073 crossed Recovery obligations | engine 2ed67b16 | no | (b) ported as `inv_073_crossed_recovery_obligations.rs`: **RED** for the 2 crossed tests (parked `#[ignore = "RED: ..."]`); the control is GREEN |
| 27 | f9f0bcf8 INV-077 exact payouts in both close orders | engine 52659c02 (resolved K/F netting, stranded payments placed at most 4 per call) | no | (a) INV-077; edits absent `inv_077_resolved_loss_settlement.rs`; vacuous at our 4-leg cap unless #740 merges |
| 28 | 8aa7a64a pin 52659c02 + INV-039 mixed-role book | 52659c02 (+ 9a219cca, 2ed67b16, 8e23d98b) | no | (a) pin bump; INV-039 change is to upstream's reference book in absent files |

Not redone here: 22863798, da0dfad9, 9199d869 (job J-20261119-PROG-TOLY-INV066) and b7990033, eb273e3c,
ea212394 (our PR #740).

## Ported tests

Command (wrapper built with `cargo build-sbf --tools-version v1.52 --features devnet`):
`cargo test -j 4 --features devnet --test v16_cu -- inv_031_provider_exit_principal inv_073_crossed`
(add `--ignored` to run the RED pair).

| Test | Engine db019142 (CI pin) | Engine 3e5970f3 (engine tip) |
|---|---|---|
| `inv_031_provider_exit_principal::v16_program_live_provider_exit_leaves_a_payment_stranded_by_a_reversal` (37849dfc) | GREEN | GREEN |
| `inv_031_provider_exit_principal::v16_program_live_backing_authority_cannot_take_a_stranded_payment_without_principal` (37849dfc) | GREEN | GREEN |
| `inv_073_crossed_recovery_obligations::v16_program_one_recovery_obligation_waits_and_the_resolved_market_drains` (2d03e07e, control) | GREEN | GREEN |
| `inv_073_crossed_recovery_obligations::v16_program_crossed_recovery_obligations_do_not_lock_the_resolved_market` (2d03e07e) | **RED**, ignored | **RED**, ignored |
| `inv_073_crossed_recovery_obligations::v16_program_asset_creator_cannot_lock_the_resolved_market_with_crossed_forfeits` (2d03e07e) | **RED**, ignored | **RED**, ignored |

The two pre-existing INV-031 tests in the same file stay GREEN on both engines.

Re-run once on this branch (job J-20261119-PROG-TOLY-TESTSWEEPb, 20 Nov), under the cargo slot lock, on both engines:
default run `5 passed; 0 failed; 2 ignored`; `--ignored` run `0 passed; 2 failed`, both panicking at
`inv_073_crossed_recovery_obligations.rs:171:9` (`nonterminal cohort reached a fixed point in round 1`). The engine-tip
run used a scratch prog worktree whose `../percolator` is at 3e5970f3, built with `PERCOLATOR_ENGINE_UNPINNED=1`
(the build script's opt-in for a local run off the CI pin) and selected with `P1_WRAPPER_SO`. The tip column
therefore shows #309/#310/#362 do not fix the INV-073 lock; 2ed67b16 is still needed.

### RED: crossed Recovery obligations lock the resolved market (2d03e07e)

`tests/invariants/cu/inv_073_crossed_recovery_obligations.rs:171` (the `assert!` in `drain_resolved_cohort`; the tests are parked with `#[ignore]` at lines 365 and 374), both crossed tests:
`crossed Recovery obligations, winner first: nonterminal cohort reached a fixed point in round 1`.
P and Q each forfeit one leg on a shut-down asset and keep a real position on the other. After resolution no
`CloseResolved` call in a whole round changes anything, so R's gain on unrelated asset 0 is never paid. In
the creator variant an account with no market role sets this up alone: it lists two assets for the fee,
crosses two of its own accounts and forfeits. This matches the upstream report against its pre-fix engine
(a55aceb3). The fix is upstream engine 2ed67b16 (a waiting Recovery obligation holds its account's other
legs only while some account still has a loss to settle or book), which neither db019142 nor the engine tip
has. There is no src change here; porting 2ed67b16 is an engine job.

Note for whoever ports 2ed67b16: both crossed tests panic on the "winner first" close order, so the
"winner last" order has never run on this fork. It needs its first green run too.

### Adaptations made in the ports (no assertion weakened except where noted)

- INV-073: `ConfigurePermissionlessResolve` has a 9,000-slot floor in this fork (upstream uses 100), so the
  resolve slot is `20 + 9,000 + 11` instead of 131.
- INV-073: upstream's drain fails on any successful no-op `CloseResolved`. This fork's wrapper returns Ok with
  no state change for an ordinary waiting close too (in the control, R, a flat winner, closes before its loser
  S; observed failing upstream's strict check before this change). The drain counts a no-op as "no progress"
  (like a refusal) instead of failing on it. A real lock still fails, because a whole round without progress
  trips the fixed-point assertion. This is the one loosening.
- INV-073 creator variant: the market account is pre-sized before each permissionless activation
  (`grow_market_capacity_for_test`), as the fork's other activation tests do, because this program cannot
  realloc a market past 10,240 bytes (note in `src/v16_program.rs` near line 275).
- INV-073: the drain, the non-admin shutdown sender and the crank hint are local helpers (upstream keeps them in
  its `v16_cu.rs`); `CloseResolved` passes the fork's NFT-registry account.
- INV-031 (37849dfc): portfolio fields are plain integers here (`.capital`, not `.capital.get()`). A refusal
  is accepted as Custom 21 (upstream's code) or Custom 25 (this fork's ledger-principal cap, which is what
  actually refuses all five withdrawals here), and must move nothing either way.
