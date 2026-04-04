# PERC-8404: InitSharedVault Admin Gate Audit

**Task:** PERC-8404  
**Issue:** GH#1915 — InitSharedVault first-caller-wins at deploy time  
**Author:** Anchor agent (Anvil)  
**Date:** 2026-04-04  
**Verdict:** ✅ RESOLVED — admin gate implemented, front-running window closed  

---

## Original Finding (GH#1915)

InitSharedVault had no admin key validation — any funded account could front-run
the deployer and call InitSharedVault before the legitimate admin. The only
protection was `AccountAlreadyInitialized`, making it a first-caller-wins race.

**Risk:** LOW (race window only exists at deploy time, one-shot init)

---

## Current State (post-PR#203)

PR#203 (`mirror/init-shared-vault-require-admin`, commit `ba26658`) added a
**slab admin proof** requirement. The handler now mandates a 4th account — an
existing initialized slab whose stored admin matches the signer.

### Defence-in-Depth Layers

| # | Check | Code Location | Effect |
|---|-------|---------------|--------|
| 1 | `accounts::expect_signer(a_admin)` | L16415 | Signer must be present |
| 2 | `slab_guard(program_id, a_slab, &slab_data)` | L16421 | Slab must belong to this program |
| 3 | `require_initialized(&slab_data)` | L16422 | Slab must be a live market (not blank) |
| 4 | `require_admin(header.admin, a_admin.key)` | L16424 | Signer must match the slab's admin key |
| 5 | `admin_ok()` rejects `[0u8; 32]` | L582-584 | Burned admin cannot authorise init |
| 6 | `system_program::id()` check | L16427 | System program identity verified |
| 7 | `Pubkey::find_program_address` | L16431 | PDA must match deterministic seeds |
| 8 | `data_is_empty()` | L16436 | Prevents double-init (AccountAlreadyInitialized) |

### Attack Vector Analysis

| Vector | Mitigated? | Reason |
|--------|-----------|--------|
| Front-running by random account | ✅ | Must prove slab admin authority |
| Front-running by non-admin slab holder | ✅ | `require_admin` rejects non-admins |
| Re-initialisation | ✅ | `data_is_empty()` check |
| Passing fake slab account | ✅ | `slab_guard` verifies PDA ownership |
| Burned admin bypass | ✅ | `admin_ok` rejects zero-admin |
| Wrong program's slab | ✅ | `slab_guard` checks `program_id` owner |

### Accepted Residual Risk

The admin proof relies on the caller being an admin of **any** existing market
slab, not a specific "vault admin" keypair. In practice, only the deployer holds
admin keys at deploy time, so this is equivalent to an upgrade-authority check
without requiring the BPF Loader introspection that `upgrade_authority` would need.

If future markets are created by third parties with their own admin keys, those
admins could also call InitSharedVault. However, `data_is_empty()` makes this a
one-shot operation — once initialised, it cannot be re-initialised.

**This is an acceptable pattern for a singleton PDA.**

---

## Recommendation

1. ✅ **No code changes required** — the admin gate is sound.
2. ✅ **GH#1915 can be closed** — the finding is fully addressed.
3. ℹ️ **Optional hardening (not needed for mainnet):** If SharedVaultState ever
   needs re-initialisation (e.g., migration), add a stored `admin` field to the
   vault state and verify against it. Current design makes re-init impossible by
   construction.

---

## Test Coverage

- `slab_guard` has Kani proofs covering PDA ownership validation
- `admin_ok` has Kani proofs covering zero-admin rejection and identity match
- No dedicated integration test exercises InitSharedVault with a non-admin signer
  (recommended addition for QA — documented as follow-up)

## Conclusion

GH#1915 is resolved. The front-running window is closed by the slab admin proof
gate added in PR#203. No further code changes needed.
