# Audit Scope

Scope definition for security review of the Percolator wrapper and its
satellite programs. Written for whoever runs the next pass — a maintainer, a
future reviewer, or an external auditor.

**As of 2026-09-21.** Every on-chain fact below was read from the cluster on
that date, not inferred from this repo. Re-derive before relying on any of it;
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
| `main` | Newest reviewed code. Not deployed anywhere. |
| `ci/deployed-refs.env` pins | What CI validates against. Accurate for **devnet**. |
| The mainnet program | Materially older than both. See below. |

State which of the three you audited, in the report, at the top.

### `ci/deployed-refs.env` does not describe mainnet

As of this writing the file pins:

```
WRAPPER_DEPLOYED=15eb8b0c599e35a1c224bfa74f92b810c78fefb7
STAKE_DEPLOYED=d0c6ecb0e063ddd024ae33afce5a43a16242aeda
NFT_DEPLOYED=215842ecf8f4683de8e0915010d1f74f1060ead3
MATCHER_DEPLOYED=d4d4f1c40efb37cbcf44e42b99a46d49c32c4dca
ENGINE_CI_SIBLING=c141d47fad9b745e9f855649b1999aecce07bd86
```

`15eb8b0c` was committed 2026-08-31. The mainnet program's ProgramData was
last written **2026-07-12**, six weeks earlier, so mainnet cannot be running
it. Devnet's was written 2026-09-01 and is consistent with the pin.

Three independent lines of evidence agree that mainnet is a different, older
generation:

1. The deploy predates the commit by six weeks.
2. ~128 commits have landed on `main` since the mainnet deploy.
3. Mainnet's single market-group account carries magic `PERCOLAT`. The current
   code requires `PERCV16\0` (`constants::MAGIC`, `src/v16_program.rs:45`) and would reject that account.

Treat `WRAPPER_DEPLOYED` as "the devnet pin" until someone re-establishes what
mainnet actually runs. Note also that the label has held at least three
different values historically (`15eb8b0c`, `f3feed5a`, `19d5d932` appear in the
file and in issue history at different times), so it has not been a reliable
record.

## 2. Program IDs and on-chain state

| | Mainnet | Devnet |
|---|---|---|
| Wrapper | `ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv` | `DhSkE7uTb8HBUYYWF1xkxMYBGtLYJEoDq1tfBD7SnHcj` |
| Stake / LP vault | not deployed | `GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3` |
| Loader | BPFLoaderUpgradeable | BPFLoaderUpgradeable |
| Program accounts | 1 (market group, rent only) | 207 (`PERCV16`) |
| Value held | ~0.67 SOL rent, **no TVL** | ~12.9 SOL, mostly rent |

Two consequences for severity calibration:

- **Nothing is currently extractable on mainnet.** There is no TVL. Findings
  against mainnet are pre-launch blockers, not live incidents. Rank them that
  way and say so, rather than inflating them.
- **Both programs are upgradeable, and both upgrade authorities are plain
  system-owned wallets** — not multisigs, not PDAs. Whoever holds either key
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
`ENGINE_CI_SIBLING`. `scripts/ci-test.sh` asserts this and also pins
`percolator-nft`, `percolator-match` and `percolator-stake`; suites that need
those programs fail at fixture setup if their `.so` files are not built.

The engine sibling was **unpinned until 2026-09-15**, so any wrapper result
published before that date was measured against whatever the engine's `main`
happened to be at the time, and is not reproducible.
