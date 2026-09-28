# Audit Scope

Scope definition for security review of the Percolator wrapper and its
satellite programs. Written for whoever runs the next pass — a maintainer, a
future reviewer, or an external auditor.

**As of 2026-09-21, devnet facts refreshed 2026-09-28 (v18.2).** The mainnet
facts below were read from the cluster on 2026-09-21; the devnet facts are
quoted from `percolator-ops/ledger/{deployments,releases}.md`, which is
re-verified on chain at every deploy. Re-derive before relying on any of it;
the section on pin drift explains why that matters.

This is not a vulnerability disclosure policy. There is currently no
`SECURITY.md` in any Percolator repo, and no stated reporting channel.

---

## 1. Decide what you are auditing first

The most common way to waste an audit pass here is to review `main` and
describe the findings as if they were live, or to review the pinned "deployed"
commit and describe them as if they applied to mainnet. Neither is true.

Three different things can be meant by "the code":

| | What it is |
|---|---|
| `main` | Newest reviewed code. Not deployed anywhere, and **not an ancestor of the deployed wrapper** (see below). |
| `ci/deployed-refs.env` `*_DEPLOYED` | The commits whose bytes run on **devnet**. Audit these for live-devnet findings. |
| `ci/deployed-refs.env` `*_CI_SIBLING` | The sibling commits CI builds and tests `main` against. They describe CI results, not the chain. |
| The mainnet program | Materially older than all of the above. See below. |

State which of the three you audited, in the report, at the top.

### What runs on devnet (v18.2, 2026-09-28)

**Deployed devnet code** (the `*_DEPLOYED` values once #513 lands; each
commit lives on a `deploy/*` branch of its repo, **not** on `main`):

| Program | Commit | Branch | Notes |
|---|---|---|---|
| wrapper | `6377376a4b089b5a9a315cee9c2f77ea2f197816` | `deploy/v18.2-wrapper` | v18.1 `3262608b` + #511; built from `sync/integration-v16` (`a9318945`) |
| engine (compiled into the wrapper) | `35ddd692098f9028947a105df27f7a9f3f85ef43` | percolator `deploy/v18.1-engine-267` | `c141d47f` + percolator#267 |
| stake | `e62aa4a17dabd502b833a8c528f785f7810417d9` | `deploy/v18.2-stake` | |
| nft | `db4aa0938f3ff0d7dcf23d21903f3e4bf8640b04` | `deploy/v18.1-nft` | |
| matcher | `12bd671b3e38da0affa47176ab14b0c4bccdfbed` | | |

The wrapper bytes are a function of **both** the wrapper and the engine
commit (path dependency), and are built with `cargo build-sbf -- --features
devnet`.

**CI build/test sources** (`*_CI_SIBLING`): `ENGINE_CI_SIBLING=35ddd692…`,
`NFT_CI_SIBLING=db4aa093…`, and `STAKE_CI_SIBLING=d0c6ecb…`. The stake CI
sibling is deliberately *not* the deployed stake: the v18 stake speaks the
integration wire that only the deployed wrapper lineage speaks, and `main`
does not contain that lineage. A green CI run therefore says "`main` is
consistent with these siblings", never "the chain is safe".

**`main` is not the deployed wrapper.** `deploy/v18.2-wrapper` descends from
`sync/integration-v16`, which carries 52 commits (~6k lines of
`src/v16_program.rs`: authority-epoch CAS, portfolio identity, intent-id
replay nonces, matcher incarnation binding, …) that were never merged to
`main` (merge-base `95aa66c3`). A finding against `main` in that code does not
automatically apply to devnet, and vice versa. Cite the commit.

### `ci/deployed-refs.env` does not describe mainnet

The mainnet program's ProgramData was last written **2026-07-12** (read
2026-09-21). Every `WRAPPER_DEPLOYED` value this file has held since then
(`15eb8b0c`, committed 2026-08-31 — 50 days later — and now `6377376a`) is
newer, so mainnet cannot be running any of them.

Three independent lines of evidence agree that mainnet is a different, older
generation:

1. The deploy predates every pinned commit (by ~7 weeks for `15eb8b0c`).
2. ~128 commits had landed on `main` since the mainnet deploy (2026-09-21 count).
3. Mainnet's single market-group account carries magic `PERCOLAT`. The current
   code requires `PERCV16\0` (`constants::MAGIC`, `src/v16_program.rs:45`) and would reject that account.

Treat `WRAPPER_DEPLOYED` as "the devnet pin" until someone re-establishes what
mainnet actually runs. A mainnet finding is only in scope as *live* once the
deployed mainnet program and its ProgramData are identified and mapped to the
cited source commit (byte-verified); a stated source commit alone is not
enough. Note also that the label has held many values historically
(`19d5d932`, `f3feed5a`, `15eb8b0c`, `6377376a`), and until 2026-09-28 it
still named the abandoned v17 wrapper after v18 went live — so confirm it
against `percolator-ops/ledger/deployments.md` before relying on it.

## 2. Program IDs and on-chain state

| | Mainnet | Devnet |
|---|---|---|
| Wrapper | `ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv` | `GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ` (v18, fresh id 2026-09-22) |
| Stake / LP vault | not deployed | `GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3` |
| NFT | not deployed | `CNGBPZRALk9Xu8BdgWNyrLJ7daQ9eJYFf1GnEEC7YCU3` |
| Matcher | `GDK8wx38kpiSVSfGTVNiSdptX3Z5R4kQyqh6Q3QX6wmi` | `4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT` |
| Loader | BPFLoaderUpgradeable | BPFLoaderUpgradeable |
| Program accounts | 1 (market group, rent only; read 2026-09-21) | re-seeded 2026-09-24 to 6 markets; not re-counted here |
| Value held | ~0.67 SOL rent, **no TVL** | devnet test funds only |

The previous devnet wrapper `DhSkE7uTb8HBUYYWF1xkxMYBGtLYJEoDq1tfBD7SnHcj`
(v17) is **abandoned**: nothing trusts it any more (the deployed nft and stake
allowlist `GnwdeQr…`). Findings against it are historical.
Devnet upgrade authority for all four programs:
`FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7`.

Two consequences for severity calibration:

- **Nothing is currently extractable on mainnet.** There is no TVL. Findings
  against mainnet are pre-launch blockers, not live incidents. Rank them that
  way and say so, rather than inflating them.
- **Both programs are upgradeable, and both upgrade authorities were read
  (2026-09-21) as plain system-owned wallets** — not multisigs, not PDAs.
  (`percolator-ops/ledger` records the mainnet authority `7JVQvrAf…` as a
  Squads multisig; the two statements disagree — re-read the account before
  citing either.) Whoever holds either key
  can replace the program wholesale. Any report that models an attacker with
  the upgrade key should say plainly that this dominates every code-level
  finding in the same report.

## 3. Surfaces

A pass should cover these seven. They partition the wrapper without
overlapping, and each has a distinct failure mode.

1. **Authority and access control** — signer/writable/owner coverage per
   handler; the marketauth, asset-admin, insurance, backing-bucket, oracle and
   protocol-fee authorities; rotation paths; PDA seed constraint.
2. **Token and value flow** — every SPL CPI; destination mint *and* owner
   checks; value conservation against engine counters; rounding direction;
   double-redeem by crank ordering.
3. **Account validation and layout** — account substitution, type confusion,
   zero-copy bounds, length checks before casts, realloc/rent, uninitialised
   state, duplicate accounts in two positions.
4. **Oracle and pricing** — oracle program-owner pinning, freshness bound to
   the same message that supplies the price, confidence, negative/zero/overflow
   handling, composite rounding, and which price applies to liquidation versus
   funding versus execution.
5. **LP vault and stake integration** — share math and first-depositor
   inflation, rounding direction on deposit versus redeem, redemption
   lifecycle, cross-program trust in the stake pool, the LP-vault expiry
   sentinel.
6. **Economic invariants** — fee bounds at *use* time not only at set time,
   liquidation reward and health direction, insurance caps and cooldowns,
   backing expiry and lien impairment, and griefing that bricks a market.
7. **Satellite programs and their trust boundary** — `percolator-nft` and
   `percolator-match`: does the wrapper pin their program IDs and owner-check
   their accounts before trusting the bytes.

### Two recurring bug classes worth targeting directly

**Sibling-path asymmetry.** A guard lands on one handler and not its
near-identical twin. Confirmed repeatedly in this codebase. For every guard
found, enumerate the sibling handlers and check each one. Note that guards
frequently use hoisted locals rather than the obvious field name, so grepping
the field name alone produces false gaps — trace the call.

**Fix loss across branches.** Reviewed, merged fixes have failed to reach
`main`. Nine PRs merged to `v17-convergence`; that branch still exists on
origin and was never merged in. Three of its fixes are confirmed absent from
`main`, and in two of the three the guard test was absent too, so CI stayed
green. A merge commit not being an ancestor of `main` proves nothing on its own
— a rebase re-lands content under a new SHA. Check the **content**, in context.

## 4. Evidence standard

A finding is reportable when all four hold:

1. It cites exact `file:line` at a stated commit, and quotes the code.
2. It gives a concrete path: who calls what, with which accounts, for what
   outcome.
3. It states reachability — permissionless, or requires which existing key.
4. It says which of the three code states (§1) it applies to.

Style issues, missing comments, and concerns with no exploit path are not
findings. A clean surface is a valid result; report it as clean rather than
padding.

## 5. Verifying a fix

**A green `cargo test` does not mean the code runs on-chain.**

`tests/v16_wrapper.rs` is a host harness. Only `tests/v16_cu.rs` loads the real
`target/deploy/percolator_prog.so` into LiteSVM. Some `solana-program` APIs are
`#[cfg(not(target_os = "solana"))]` real and `#[cfg(target_os = "solana")]`
`unimplemented!()` — they compile for SBF and panic at runtime. `cargo check`,
clippy and `cargo-build-sbf` all stay green.

`Pubkey::is_on_curve()` is one such API (`solana-program` 1.18.26 and 2.0.25,
`pubkey.rs:163-172`). A proposed auth guard using it passed the host suite and
would have panicked on every deposit, withdraw and trade, freezing all
collateral with no admin exit. It was caught only by building the `.so` and
running LiteSVM.

So, for any change touching shared helpers or auth paths:

- `cargo build-sbf --features devnet` then `cargo test --test v16_cu`, A/B'd
  against baseline **in the same checkout**, comparing panic-line counts.
- Compare the host failing set against `tests/KNOWN_FAILING.txt`, not against
  zero. Several allowlisted failures are `UnsupportedSysvar` harness limits and
  are not defects.
- Prefer testing *whether a key signed* over testing a key's *shape*. PDAs
  legitimately sign via CPI, and roughly half of arbitrary 32-byte values are
  valid curve points.

**Every regression test must fail without the fix.** Revert only the source,
keep the test, and confirm it flips. A test that passes both ways guards
nothing. Where a test asserts that something is *preserved*, pair it with a
control that fails if the underlying field simply stopped being written.

## 6. Environment

The wrapper has a path dependency on `../percolator` (the engine), so the
engine must be checked out as a sibling directory at the pinned
`ENGINE_CI_SIBLING`; `build.rs` refuses to build otherwise (#510), and
`scripts/ci-test.sh` asserts it too. CI checks out `percolator-match` at
`MATCHER_DEPLOYED`, `percolator-nft` at `NFT_CI_SIBLING` and
`percolator-stake` at `STAKE_CI_SIBLING` from `ci/deployed-refs.env`, and
`ci-test.sh` builds their `.so` files before the suite runs.

The engine sibling was **unpinned until 2026-09-15**, so a wrapper result
published before that date *that does not state its engine commit* was
measured against whatever the engine's `main` happened to be at the time, and
is not reproducible. Results that record the engine commit are reproducible
at that commit.
