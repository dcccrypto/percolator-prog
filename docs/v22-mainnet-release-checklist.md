# v2.2 mainnet release checklist (wrapper SBF)

Wrapper-side items that must be TRUE of the exact artifact that is deployed. Source: security
review of Wave B (W-M2, rounds 2 and 3). This is a checklist for the release owner; nothing
here deploys anything.

## 1. The artifact is a mainnet build (no `devnet` feature)

The band caps are compile-time constants selected by `cfg(feature = "devnet")`: a devnet build
allows lambda 10x and alpha 70% on band markets, a mainnet build 3x and 60%. Also behind
`devnet`: the devnet stake program id and the devnet vault-LP matcher id.

```
cargo build-sbf --sbf-out-dir out/mainnet            # NO --features devnet
scripts/check-mainnet-sbf.sh out/mainnet/percolator_prog.so
```

`check-mainnet-sbf.sh` must print `PASS`. It checks the build-flavor string in the image
(`PERCOLATOR_BUILD_FLAVOR=mainnet.`, logged by InitMarket) and re-runs
`sec_band_caps_by_build` without the feature. It FAILS on a `--features devnet` artifact (that
is its negative control; run it once on the devnet `.so` to see it fail).

The marker is an accident guard, not tamper evidence: a hostile builder could embed both
strings. Item 2 is the tamper check.

## 2. Reproducible-build hash comparison

The deployed bytes must equal an independent rebuild of the tagged commit.

1. Two people (or two clean machines) check out the SAME wrapper commit and the SAME engine
   commit (`../percolator`, the path dependency) at the SAME absolute path. The bytecode is
   path-dependent: a different checkout path gives different `.text`, so use the canonical
   path recorded in `ledger/deployments.md` for the release.
2. Same toolchain: `cargo-build-sbf` and platform-tools exactly as pinned in
   `scripts/sbf-frame-gate.sh` (the script refuses any other version).
3. Each runs `cargo build-sbf --sbf-out-dir out/mainnet` and `shasum -a 256
   out/mainnet/percolator_prog.so`.
4. The two hashes must be identical, and identical to the hash of the file handed to the
   deploy step. Record the hash, both commits and the toolchain in `ledger/deployments.md`.
5. After deploy: `solana program dump <program id> onchain.so`, trim to the artifact length,
   and compare its hash with the recorded one.

A mismatch at any step stops the release.

## 3. Gates that must be green on that commit

- `scripts/sbf-frame-gate.sh` prints `SBF FRAME GATE: OK`.
- Engine suites (default, audit-scan, fuzz, fork-facade) and the wrapper suite against the
  pinned sibling binaries: failing set equals the recorded baseline, nothing new.
- `tests/v16_cu.rs` (the 11-leg batch budget).
- Sibling programs rebuilt against the v2.2 layout in the same flag day (stake offsets and a
  VERSION == 19 guard; NFT re-vendor with the exact portfolio length). Off-chain decoders
  (SDK, keeper, indexer) guard on VERSION == 19.
- Kani: the B-series design run once on the final code, every harness SUCCESSFUL with its
  covers satisfied.
- D-1 founder sign-off recorded in the ledger.

## 4. Keeper switches

- Tag 118 (dust sweep) only against a deployment that carries the bilateral sweep
  (4 accounts). Leave it OFF otherwise.
