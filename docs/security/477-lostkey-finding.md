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
| `WithdrawInsurance` (tag 41, terminal insurance; the counterpart of upstream's terminal `WithdrawInsuranceAsset`) | `handle_withdraw_insurance`, Resolved and empty only | none (an unsigned call settles the authority's whole reserve) | either |
| `WithdrawInsuranceAsset` (tag 57) | `handle_withdraw_insurance_asset` | Live only, operator signs | signer's own choice |

Three paths are therefore exposed, as in upstream: the two backing paths and the terminal
insurance payout (tag 41). Tag 57 needs the operator's signature in this tree.

## Result

Tests: `v16_inv018_lostkey_backing_payout_is_either_mint_pinned` and
`v16_inv018_lostkey_terminal_insurance_payout_is_either_mint_pinned`
(`tests/invariants/cu/inv_018_reserve_payout_lostkey.rs`). Both run the same scenario; the
table is the backing-bucket one, and the insurance one has the same balances (100 / 0 / 100,
then 100 to `marketauth`). Run on the base program
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
and then take the primary vault through `CloseSlab`. The backing authority's primary tokens
end up with the creator.

A frozen or otherwise unusable primary vault is the one case where the primary-only rule could
block a payout; for the creator-fee payee route the pot is then re-booked to the protocol leg
after the payee grace period (`rebook_orphaned_fee_legs_view`), so `CloseSlab` is not wedged.

## Why the code is not changed here

The rule "unsigned means primary" cannot be applied to these paths without removing the
lost-key guarantee they exist for (beneficiaries that dropped their keys must stay payable).
Upstream states the same trade-off in its README threat model ("the insurance and backing
authorities of a market trust its marketauth with the reserves they fund"); that paragraph is
not part of this tree's README, so this document carries it. Changing the code here would
deviate from upstream.

## Stake reserve and creator-fee payouts

These two do not fall under the exception (it names only the three paths above), so they were
given the `0b06131f` rule instead of being documented. Open point on the stake route: the
wrapper does not check the stake pool's recorded collateral mint, so a pool whose vault were held
in the secondary mint could no longer be paid and would count as owed at `CloseSlab` (no grace
fallback, unlike the creator-fee payee). That needs a stake program that lets a pool be created
on a mint other than the market's primary; it could not be checked from this repo. See see the PR for the tests
`v22_inv018_unsigned_stake_reserve_payout_is_primary_mint` and
`v22_inv018_unsigned_creator_fee_payout_is_primary_mint`.

## Options for a decision

1. Accept and document (upstream's position). Funders check the secondary mint before funding.
2. Refuse a secondary mint on these two backing paths unless the beneficiary signs, and accept
   that a beneficiary with a dropped key then cannot be paid in the secondary mint (it can
   still be paid in the primary mint, which always covers the claim).
3. Make `CloseSlab` refuse to pay out primary surplus while a secondary payout has displaced it.
