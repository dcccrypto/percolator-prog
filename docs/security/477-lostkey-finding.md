# #477 follow-up: reserve payouts that stay payable in either mint (lost-key exception)

Status: finding, **code unchanged** (same as upstream `0b06131f`). Recorded for a decision.

## What the port changes and what it leaves

`0b06131f` makes a resolved *portfolio* payout that the owner did not sign (`CloseResolved`,
`ClaimResolvedPayoutTopup`) use the primary mint only. It deliberately leaves reserve payouts
alone, because their beneficiaries may have dropped their keys and the payout has to stay
possible without them:

| path | this tree | signature needed | mint |
|---|---|---|---|
| `WithdrawBackingBucket` (tag 50) | `verify_domain_withdrawal_preflight`, `src/v16_program.rs` | none once Resolved | either |
| `WithdrawBackingBucketEarnings` | same preflight | none once Resolved | either |
| `WithdrawInsuranceAsset` | same preflight, but this tree allows it only in Live mode and with the operator's signature | operator signs | either (signer's own choice) |

The terminal `WithdrawInsuranceAsset` of the upstream note has no unsigned Resolved form in this
tree (`handle_withdraw_insurance_asset` requires `mode == Live`), so only the two backing paths
are exposed.

## Result

Test: `v16_inv018_lostkey_backing_payout_is_either_mint_pinned`
(`tests/invariants/cu/inv_018_reserve_payout_lostkey.rs`). Run on the base program
(`d27f3d73`) and on the fixed program; the result is identical, as intended.

Setup: the creator (`marketauth`) names a secondary mint on the empty market; the backing
authority (a distinct key) funds a backing bucket with 100 primary tokens and then signs
nothing more; the market is resolved; the secondary vault holds 100 of the creator's mint.

| step | beneficiary (secondary) | secondary vault | primary vault | marketauth primary |
|---|---|---|---|---|
| before the payout | 0 | 100 | 100 | 0 |
| `WithdrawBackingBucket`, submitted by anyone, no signature from the beneficiary, dest in the secondary mint | 100 | 0 | 100 | 0 |
| `CloseSlab` by `marketauth` | 100 | 0 | 0 | 100 |

So a creator who controls the secondary mint can pay a backing authority in its own mint
and then sweep the primary vault through `CloseSlab`. The backing authority's primary tokens
end up with the creator.

## Why the code is not changed here

The rule "unsigned means primary" cannot be applied to these paths without removing the
lost-key guarantee they exist for (beneficiaries that dropped their keys must stay payable).
Upstream states the same trade-off in the README threat model ("the insurance and backing
authorities of a market trust its marketauth with the reserves they fund"). Changing it here
would deviate from upstream.

## Stake reserve and creator-fee payouts

These two do not fall under the exception (it names only the three paths above), so they were
given the `0b06131f` rule instead of being documented: see the PR for the tests
`v22_inv018_unsigned_stake_reserve_payout_is_primary_mint` and
`v22_inv018_unsigned_creator_fee_payout_is_primary_mint`.

## Options for a decision

1. Accept and document (upstream's position). Funders check the secondary mint before funding.
2. Refuse a secondary mint on these two backing paths unless the beneficiary signs, and accept
   that a beneficiary with a dropped key then cannot be paid in the secondary mint (it can
   still be paid in the primary mint, which always covers the claim).
3. Make `CloseSlab` refuse to sweep primary surplus while a secondary payout has displaced it.
