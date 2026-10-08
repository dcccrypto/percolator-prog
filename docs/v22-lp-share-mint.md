# v2.2: LP / Earn share mint decimals, name and icon (prog#542)

Applies to vaults created by a build that carries this change. A mint's `decimals` is immutable,
so a vault created by an earlier build keeps a 0-decimal share mint for good (tag 122 still
names it).

## Tag 74 `CreateLpVault`: one more REQUIRED account

Instruction data is unchanged. The account list gains a 7th entry:

| # | account | flags |
|---|---|---|
| 0 | marketauth | signer, writable |
| 1 | market | writable |
| 2 | LP vault registry PDA `["lp_vault", market]` | writable |
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

## Tag 122 `InitLpShareMetadata`: the share token's name, symbol and uri

One instruction, two forms, selected by the ticker length.

Data: `[122][n: u8][n ticker bytes]`, `n` in `0..=8`. The length byte is mandatory (`[122]`
alone is refused), `n > 8` and trailing bytes are refused at decode.

| # | account | flags |
|---|---|---|
| 0 | payer; for `n > 0` this MUST be `config.marketauth` | signer, writable |
| 1 | LP vault registry PDA | readonly |
| 2 | LP share mint PDA | readonly |
| 3 | Metaplex metadata PDA `["metadata", metaqbxx..., mint]` under the Token Metadata program | writable |
| 4 | Metaplex Token Metadata program `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | |
| 5 | system program | |
| 6 | the market, **only for `n > 0`** (read for `marketauth`; never passed to Metaplex) | readonly |

### What is written

| | generic form (`n == 0`) | ticker form (`n > 0`) |
|---|---|---|
| who | anyone | `config.marketauth` of this market, signing as `[0]` |
| name | `Percolator Earn Share ` + first 8 base58 characters of the market address | `TICKER` + ` Earn Share - Percolator` |
| symbol | `pEARN` | `pe` + `TICKER` |
| uri | `<BASE>/api/earn-share/<market address, base58>` | the same |

Examples (devnet build):

```text
market Azagguvr... , ticker SOL
  name   SOL Earn Share - Percolator
  symbol peSOL
  uri    https://play.percolator.trade/api/earn-share/Azagguvr...(full address)

market BeumQKPd... , ticker BURNIE
  name   BURNIE Earn Share - Percolator
  symbol peBURNIE
  uri    https://play.percolator.trade/api/earn-share/BeumQKPd...(full address)

market BeumQKPd... , nobody authorised ever named it (generic)
  name   Percolator Earn Share BeumQKPd
  symbol pEARN
  uri    https://play.percolator.trade/api/earn-share/BeumQKPd...(full address)
```

Fixed for both: seller fee 0, no creators, `is_mutable = true`, update authority = the registry
PDA.

### Ticker rules

* 1 to 8 bytes, each `A-Z` or `0-9`. Anything else (lowercase, space, `.`, `-`, `$`, NUL,
  non-ASCII) is refused with `InvalidInstruction` (Custom 9).
* 8 is the hard limit: Metaplex allows a 10-byte symbol (`pe` + 8). With 8 the name is exactly
  Metaplex's 32 bytes. This is also why the separator is ` - ` and not ` · `: `·` is two bytes
  in UTF-8 and an 8-character ticker would make the name 33.
* **The ticker is chosen by the market creator and is NOT verified**, exactly like the market's
  name in the app. The creator of a junk market can call its share `USDC`. What the caller
  cannot do is remove the framing: the name always ends in ` Earn Share - Percolator`, the
  symbol always starts with lowercase `pe` (a ticker is uppercase and digits only, so a share
  symbol can never equal a ticker), and the uri takes no caller input. A reserved-word list is
  deliberately not used: it would not be sufficient protection.
* The app's own symbol limit is 20 characters of `[A-Za-z0-9._-]` (`app/lib/market-metadata.ts`
  `SYMBOL_MAX_LEN`, `origin/playground`). The client must reduce it before sending: uppercase,
  drop every character outside `A-Z 0-9`, keep the first 8; if nothing is left, send the
  generic form. The program never truncates; it refuses.

### Who may set the ticker, and why

`config.marketauth`, read live from the market account passed at `[6]` (which must be the
registry's own market and owned by this program). It is the signer tag 74 already requires to
create the vault, so the launch flow sends 74 and 122 with the one signer it already has (proven
in one transaction). It is also the only party the program knows that speaks for the market: it
already sets the market's parameters and can pause or close the vault. If `marketauth` is later
handed to a keyless address, nobody can set a ticker any more; the generic form remains
available to everyone.

### State machine (no wrapper account is written; the record itself is the state)

| record before | `n == 0` (anyone) | `n > 0` (marketauth) |
|---|---|---|
| none | create GENERIC | create TICKER |
| GENERIC | refused, `AlreadyInitialized` (Custom 2) | **update to TICKER, once** |
| TICKER | refused, `AlreadyInitialized` | refused, `AlreadyInitialized` |

* The permissionless fallback means a vault is never stuck as "Unknown Token", and it can never
  lock the proper name out: marketauth can still upgrade a generic record.
* "Once" is enforced by reading the Metaplex record: the upgrade is signed only if the record is
  a `MetadataV1` for this mint, its update authority is the registry PDA and its name is still
  this market's generic name. After the upgrade the name is the ticker form, so a second call
  is refused. An unrecognised layout is treated as "not generic" (no update is signed).
* A ticker cannot be changed, and a ticker record cannot go back to generic.

### Mutability

The record is created **mutable**, with the registry PDA as update authority.

* Only this program can sign for the registry PDA, and the only update it signs is the
  generic -> ticker upgrade above. There is no instruction that changes a ticker record.
* What mutability adds to the Metaplex CPI: one more call shape, `UpdateMetadataAccountV2`,
  which receives ONLY the metadata PDA (writable) and the registry PDA (signer). That is less
  than the create call (which also carries the payer and the system program). No mint, token
  program, token account, market or ledger is passed in either call.
* A hostile upgrade of the Metaplex program: it OWNS every metadata account, so it could rewrite
  any record whatever the `is_mutable` flag says; the flag is enforced by Metaplex itself.
  Immutability would therefore not have protected the name against that program, and
  mutability gives it nothing new: with the registry PDA's signature it still cannot mint, burn
  or move shares (the mint is read-only in create and absent in update; no token program is in
  the call), cannot touch wrapper state (not passed; A -> B -> A reentrancy is refused by the
  runtime), and in create can at most spend the caller's own lamports.
* What it buys: the uri base is a compile-time constant. If the domain ever has to change, a
  later program upgrade can add a narrowly scoped update path (registry PDA signs) and correct
  existing records. With immutable records that would be impossible. Today no such path exists.
* The trade: "the name can never change" is a property of this program's code (and of whoever
  holds its upgrade authority), not of the Metaplex record.

### URI

`LP_SHARE_URI_BASE + "/api/earn-share/" + base58(market)`, built on chain, no caller input,
at most 88 bytes (limit 200).

| build | constant | value |
|---|---|---|
| `--features devnet` | `lp_share_meta_v22::LP_SHARE_URI_BASE_DEVNET` | `https://play.percolator.trade` |
| default (mainnet) | `lp_share_meta_v22::LP_SHARE_URI_BASE_MAINNET` | `https://percolator.trade` (**FOUNDER DECISION**: the builder's default; confirm before a mainnet build) |

Both are pinned by the unit test `uri_bases_are_pinned`.

### The JSON the app must serve (not built here)

`GET <BASE>/api/earn-share/<market>` -> `200`, `Content-Type: application/json`,
`Access-Control-Allow-Origin: *`, no authentication, cacheable (suggest
`Cache-Control: public, max-age=300`). `<market>` is the market (slab) address in base58.

```json
{
  "name": "BURNIE Earn Share - Percolator",
  "symbol": "peBURNIE",
  "description": "Share of the Earn vault of the BURNIE market on Percolator (market BeumQKPd...). The ticker is set by the market creator and is not verified by Percolator.",
  "image": "https://play.percolator.trade/api/earn-share/BeumQKPd.../image",
  "external_url": "https://play.percolator.trade/earn/BeumQKPd...",
  "properties": {
    "category": "image",
    "files": [{ "uri": "https://play.percolator.trade/api/earn-share/BeumQKPd.../image", "type": "image/png" }]
  }
}
```

* `name` and `symbol` MUST be read from the on-chain Metaplex record (PDA
  `["metadata", metaqbxx..., lp_vault_mint(market)]`), not from the app database, so the JSON
  never disagrees with what the chain says. If the record does not exist yet, return the
  generic form (`Percolator Earn Share <first 8>`, `pEARN`).
* `image`: `GET <BASE>/api/earn-share/<market>/image` -> a square PNG (512 x 512): the market
  token's logo with a Percolator badge in a corner; when the token has no logo, the Percolator
  mark alone. It must be a stable URL (wallets cache by URL).
* `external_url`: the market's Earn page, `<BASE>/earn/<market>`.
* Unknown market (no LP vault registry for that address): `404`.
* The route must keep working for as long as share tokens exist, for both forms, on the host
  named by the build's base constant.

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
