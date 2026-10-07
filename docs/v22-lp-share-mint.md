# v2.2: LP / Earn share mint decimals and name (prog#542)

Applies to vaults created by a build that carries this change. A mint's `decimals` is immutable,
so a vault created by an earlier build keeps a 0-decimal share mint for good.

## What changed on the wire

### Tag 74 `CreateLpVault`: one more REQUIRED account

Instruction data is unchanged. The account list gains a 7th entry:

| # | account | flags |
|---|---|---|
| 0 | marketauth | signer, writable |
| 1 | market | writable |
| 2 | LP vault registry PDA `["lp_vault_registry", market]` | writable |
| 3 | LP share mint PDA `["lp_vault_mint", market]` | writable |
| 4 | system program | |
| 5 | SPL Token program (classic) | |
| 6 | **the market's primary collateral mint** | readonly |

* `[6]` must equal `config.collateral_mint` (else `InvalidArgument`) and be a classic SPL mint
  of exactly `Mint::LEN` bytes (else `InvalidMint`, Custom 10).
* The six-account form is refused with `NotEnoughAccountKeys`. There is no fallback to a
  0-decimal mint.
* The share mint is initialised with `decimals = collateral mint decimals`. Authority (registry
  PDA), freeze authority (none) and address are unchanged.

### Tag 122 `InitLpShareMetadata`: new, permissionless

Data: the single byte `122`. Accounts:

| # | account | flags |
|---|---|---|
| 0 | payer (pays the metadata rent and the Metaplex create fee, about 0.0151 SOL in total) | signer, writable |
| 1 | LP vault registry PDA | readonly |
| 2 | LP share mint PDA | readonly |
| 3 | Metaplex metadata PDA `["metadata", metaqbxx..., mint]` under the Token Metadata program | writable |
| 4 | Metaplex Token Metadata program `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | |
| 5 | system program | |

It CPIs `CreateMetadataAccountV3` with the registry PDA signing as mint authority. The content
is fixed by the program, with no caller input:

```text
name   = "Percolator Earn Share " + first 8 base58 characters of the market address
symbol = "pEARN"
uri    = ""            seller fee 0, no creators, is_mutable = false
update authority = the registry PDA (no instruction signs an update)
```

It can run any time after tag 74, by anyone, once per mint (Metaplex refuses an existing
metadata account, Custom 199 from that program). It reads no price and writes no account of
this program. It also works on a vault created by an older build (0-decimal mint): the name
appears, the decimals stay 0.

## What did NOT change

* The share:atom scale. Genesis still mints one RAW share per collateral atom, minus the 1,000
  dead shares (`LP_VAULT_MINIMUM_LIQUIDITY`). Raw share counts for a given deposit are the same
  as before; only how a wallet renders them moved (`raw / 10^decimals`).
* Every pricing function (`lp_shares_for_deposit`, `lp_atoms_for_redemption`,
  `senior_shares_for_deposit`, `senior_atoms_for_redemption`, `rescue_shares`, the bond and
  junior math) and every rounding direction. None of them reads a mint.
* Account layouts, error codes, the registry, tags 75 / 76 / 77 / 78 / 79 / 80 / 112.
* The token program: the share mint is still a classic SPL Token mint.

## Residual

`UpdateBaseUnitMints` can switch an EMPTY market (vault, `c_tot`, insurance all zero) to a
collateral mint with different decimals. An LP vault created before such a switch keeps the
old decimals on its share mint: a display mismatch only (raw accounting is unaffected).
