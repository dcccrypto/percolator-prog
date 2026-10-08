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

One instruction, two forms, selected by the ticker length. It is deliberately NOT part of
tag 74: creating a market never depends on the Metaplex program (security review R11).

Data: `[122][n: u8][n ticker bytes]`, `n` in `0..=8`. The length byte is mandatory (`[122]`
alone is refused), `n > 8` and trailing bytes are refused at decode.

| # | account | flags |
|---|---|---|
| 0 | payer: funds the record. Anyone. Never handed to Metaplex | signer, writable |
| 1 | LP vault registry PDA `["lp_vault", market]` | readonly |
| 2 | LP share mint PDA `["lp_vault_mint", market]` | readonly |
| 3 | Metaplex metadata PDA `["metadata", metaqbxx..., mint]` under the Token Metadata program | writable |
| 4 | Metaplex Token Metadata program `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | |
| 5 | system program | |
| 6 | fee-payer PDA `["lp_share_meta_payer", mint]` under the wrapper | writable |
| 7 | the market, **only for `n > 0`** (read for `marketauth`; never passed to Metaplex) | readonly |
| 8 | `config.marketauth`, **only for `n > 0`** (never passed to Metaplex) | signer |

`[0]` and `[8]` may be the same wallet (the launch flow: the creator pays and is marketauth).

### What is written

| | generic form (`n == 0`) | ticker form (`n > 0`) |
|---|---|---|
| who | anyone | `config.marketauth` of this market signs as `[8]` |
| name | `Percolator Earn Share ` + first 8 base58 characters of the market address (30 bytes) | `Percolator Earn ` + `TICKER` + ` ` + first 6 base58 characters of the market address (max 31 bytes) |
| symbol | `pEARN` | `pe` + `TICKER` (max 10 bytes) |
| uri | `<BASE>/api/earn-share/<market address, base58>` | the same |
| `is_mutable` | **true** | **false** (frozen at birth, or by the upgrade) |

Worked examples at the MAXIMUM ticker length (8), devnet build, two markets that both chose
`1000PEPE`:

```text
market Azagguvr... (full address A), ticker 1000PEPE
  name   Percolator Earn 1000PEPE Azaggu          (31 bytes)
  symbol pe1000PEPE                               (10 bytes)
  uri    https://play.percolator.trade/api/earn-share/<A>

market BeumQKPd... (full address B), ticker 1000PEPE
  name   Percolator Earn 1000PEPE BeumQK          (31 bytes)
  symbol pe1000PEPE                               (10 bytes)
  uri    https://play.percolator.trade/api/earn-share/<B>

market BeumQKPd..., ticker BURNIE:  Percolator Earn BURNIE BeumQK / peBURNIE
market BeumQKPd..., never named by its creator (generic):
  name   Percolator Earn Share BeumQKPd / symbol pEARN / same uri
```

Fixed for both: seller fee 0, no creators, no collection, update authority = the registry PDA.

### Name layout and spoofing (security review R9)

* **The framing leads.** Every name starts with `Percolator Earn `, so a wallet that truncates
  the name shows `Percolator E…`, never `USDC Earn Sh…`. The symbol always starts with
  lowercase `pe`; a ticker is uppercase and digits only, so a share symbol can never equal a
  ticker. The caller cannot remove or reorder any of it.
* **The market fragment stays in the name.** Two markets with the same ticker get different
  names (the last 6 characters). They get the SAME symbol: `pe` + an 8-character ticker fills
  Metaplex's 10 bytes, so there is no room for a fragment there. The fragment is a
  disambiguator, not proof of authenticity (6 base58 characters can be ground).
* **The ticker is chosen by the market creator and is NOT verified**, exactly like the market's
  name in the app. The creator of a junk market can call its share `USDC`; the result reads
  `Percolator Earn USDC <market>` / `peUSDC`. No reserved-word list is used: it would not be
  sufficient protection.
* `Share` is dropped from the ticker form to make room: `Percolator Earn Share ` (22) + an
  8-character ticker (8) leaves 2 of Metaplex's 32 bytes, not enough for a market fragment.

### Ticker rules

* 1 to 8 bytes, each `A-Z` or `0-9`. Anything else (lowercase, space, `.`, `-`, `$`, NUL,
  non-ASCII) is refused with `InvalidInstruction` (Custom 9).
* 8 is the hard limit: Metaplex allows a 10-byte symbol (`pe` + 8).
* The app's own symbol limit is 20 characters of `[A-Za-z0-9._-]` (`app/lib/market-metadata.ts`
  `SYMBOL_MAX_LEN`, `origin/playground`). The client must reduce it before sending: uppercase,
  drop every character outside `A-Z 0-9`, keep the first 8; if nothing is left, send the
  generic form. The program never truncates; it refuses.

### Who may set the ticker, and why

`config.marketauth`, read live from the market account at `[7]` (which must be the registry's
own market, `registry.market_group`, and owned by this program), signing as `[8]`. It is the
signer tag 74 already requires to create the vault, so the launch flow sends 74 and 122 with
the one signer it already has (proven in one transaction). It is the only party the program
knows that speaks for the market. If `marketauth` is later handed to a keyless address, nobody
can set a ticker any more; the generic form remains available to everyone. The app must
therefore name the share in the launch flow.

### State machine (no wrapper account is written; the Metaplex record is the state)

"Ours" = the metadata PDA is owned by the Metaplex program, is a `MetadataV1` for this mint,
and its update authority is the registry PDA.

| record before | `n == 0` (anyone) | `n > 0` (marketauth) |
|---|---|---|
| none | create GENERIC (mutable) | create TICKER (immutable) |
| ours, mutable, exactly the generic content | refused, `AlreadyInitialized` (Custom 2) | update to TICKER and freeze |
| ours, mutable, any other content | **rewritten to GENERIC** | update to TICKER and freeze |
| ours, immutable | refused, `AlreadyInitialized` | refused, `AlreadyInitialized` |
| not ours (other update authority, other mint, unparseable) | refused, `AlreadyInitialized` | refused, `AlreadyInitialized` |

* A permissionless generic record can never lock out the authorised name (R7), and the generic
  call can never overwrite a ticker record: a ticker record is immutable, and the latch is
  Metaplex's own `is_mutable` flag, not something inferred from the name (R8).
* **A record somebody else created is repaired, not fatal (R6).** Metaplex's source has a
  seed-authority path that lets a Metaplex-held key create metadata for any SPL mint that has
  none: mutable, update authority = the mint authority, i.e. our registry PDA. Such a record,
  or one whose content was changed, is rewritten to the generic content by ANY caller, or taken
  straight to the ticker form by marketauth. A record that is immutable, or whose update
  authority is not the registry PDA, cannot be changed by this program at all; the share then
  keeps whatever that record says (cosmetic; no instruction of this program reads it).
* A ticker cannot be changed, and a ticker record cannot go back to generic.
* An update makes Metaplex pad name / symbol / uri with NUL bytes to 32 / 10 / 200; readers
  must trim trailing NULs (the program's own reader does).

### Mutability (security review R8) — FOUNDER DECISION

Built as the reviewer recommended: **generic records are mutable, ticker records are
immutable** (created with `is_mutable = false`, or frozen by the upgrade with
`is_mutable = Some(false)`).

| | freeze on ticker (built) | mutable for ever |
|---|---|---|
| "a ticker is set once" | enforced by Metaplex's own flag | inferred from record content, which a hostile Metaplex upgrade can forge |
| a later program upgrade can correct the uri base of named records | **no, never** | yes (a new, narrow update path signed by the registry PDA) |
| a later program upgrade can rename a named share | no | yes (so "the name cannot change" would rest on this program's upgrade authority) |

The cost of the built form: **once a share is named with a ticker, its uri can never be
corrected**. The base domain in the build is then a permanent trust anchor (below). Switching
to "mutable for ever" is two booleans in `handle_init_lp_share_metadata` plus the content
latch; say so before the release is cut.

The update authority is the registry PDA in every case and is never reassigned
(`new_update_authority = None`, pinned byte-exact). `is_mutable = false` blocks data changes
only; Metaplex would still let the update authority be reassigned, but only this program can
sign for the registry PDA and it has no instruction that does.

### What Metaplex is given (security review R1-R5), and the exposure (R11)

| | create (`CreateMetadataAccountV3`, ix 33) | update (`UpdateMetadataAccountV2`, ix 15) |
|---|---|---|
| program | pinned by key to `metaqbxx...`; discriminators are compile-time constants | same |
| accounts | metadata PDA (w), mint (**read-only**, whatever the outer tx says), registry PDA (signer), fee-payer PDA (signer, w), registry PDA, system program | **exactly two**: metadata PDA (w), registry PDA (read-only signer) |
| never passed | the caller's wallet, marketauth, any token program, token account, market, ledger, escrow | the same, and no payer, no mint |
| data | `DataV2`, seller fee 0, creators / collection / uses `None` | `Some(DataV2)` as left, `new_update_authority = None`, `primary_sale_happened = None`, `is_mutable = None` or `Some(false)` |

* **No user signature and no privileged signature ever enters a Metaplex CPI (R3).** The
  wrapper moves `LP_SHARE_META_FUND_LAMPORTS` (0.03 SOL) from the caller to the fee-payer PDA
  with a System Program CPI, lets Metaplex charge the PDA (today 15,115,600 lamports: rent for
  607 bytes + Metaplex's create fee), and returns the remainder to the caller in the same
  instruction. The PDA ends at 0 lamports. marketauth signs the wrapper instruction only.
* **Exposure if the Metaplex program is upgraded to something hostile:** it can write a wrong
  record for the share token (it owns every metadata account anyway) and keep the lamports in
  the fee-payer PDA for that one call (at most 0.03 SOL plus anything a third party parked
  there). That is all: it cannot mint, burn, move or re-authorise shares (the mint is read-only
  and no token program is in the call), cannot touch wrapper state (nothing of ours is passed
  writable; A -> B -> A reentrancy is refused by the runtime), and cannot reach the caller's or
  marketauth's wallet. The exposure is cosmetic plus that bounded fee.
* Bindings (R5): the registry must be owned by this program, of kind LP-vault-registry and the
  current version, and equal to the PDA derived from its own `market_group`; the mint must
  equal BOTH the PDA derived from that market and `registry.lp_mint` (a mint whose authority
  merely happens to be the registry PDA is refused); the metadata PDA and the fee-payer PDA
  are derived on chain.

### The fund constant and the fee-payer PDA (review round 2: F2, F4, F5)

* **F2. The caller must HOLD `LP_SHARE_META_FUND_LAMPORTS` = 30,000,000 lamports (0.03 SOL)
  to create a record, although the net cost is 15,115,600.** The difference comes back in the
  same instruction. A caller with less is refused by the System Program (`Custom(1)`,
  insufficient lamports) and loses nothing. The same constant is a CEILING: if Metaplex's rent
  plus fee for a record ever rises above 0.03 SOL, creates fail until this program is upgraded
  (updates and repairs, which move no lamports, keep working). The constant is kept on purpose:
  it is the most a hostile callee can take per call. Tested with a hostile stand-in at the
  Metaplex id (`tests/fixtures/hostile_mpl`): the caller loses exactly 30,000,000 or nothing,
  marketauth nothing, wrapper state nothing.
* **F4. Lamports sent to the fee-payer PDA after a record exists are stranded.** The PDA is
  swept to the caller only by a CREATE; the update path never touches it. Anything parked
  there once the share is named stays there (the sender's loss; no instruction can move it).
  Lamports parked BEFORE the create go to whoever creates the record.
* **F5. A record seeded with a verified collection would make updates fail.** If the
  pre-existing record (R6) carried a verified collection, Metaplex refuses an update that sets
  `collection = None`, so the repair and the ticker upgrade would fail and the share would
  keep that record. Only the Metaplex program (or a key it trusts) can produce such a record
  for our mint: the same trust class as a hostile upgrade, and cosmetic.

### Decisions for the founder (collected)

1. **Mainnet uri base** (`https://percolator.trade` is the builder's default) and the
   commitment to hold that domain for as long as share tokens exist.
2. **The `/api/earn-share/<market>` endpoint must exist on that host before ANY share is named
   on mainnet.** A ticker record is immutable; its uri cannot be pointed elsewhere later.
3. **Freeze on ticker (built) or mutable for ever** (the uri is then correctable by a later
   program upgrade, at the cost described under Mutability).
4. **marketauth can turn generic into ticker once, at any time, including after deposits.**
   Holders who saw `Percolator Earn Share <market>` / `pEARN` will then see
   `Percolator Earn <TICKER> <market>` / `pe<TICKER>`. The framing and the market fragment
   stay; the ticker is unverified.
5. **Two markets with the same ticker share a symbol** (`pe<TICKER>`); only the name differs.
   Alternative: cap tickers at 6 characters to fit a 2-character market fragment.
6. **The 0.03 SOL fund constant** (F2): the balance a caller must hold, the ceiling on
   Metaplex's charge, and the bound on hostile-callee loss, all in one number.
7. Accepting the third-party-upgradeable Metaplex program as a dependency of this one optional
   instruction; whether `UpdateBaseUnitMints` should refuse a decimals change once an LP vault
   exists (review Info-1, not changed here).

### URI (security review R10)

`LP_SHARE_URI_BASE + "/api/earn-share/" + base58(market)`, built on chain, no caller input,
at most `LP_SHARE_URI_MAX_LEN` bytes (const-asserted `<= 200`; 89 on devnet, 84 on mainnet).

| build | constant | value |
|---|---|---|
| `--features devnet` | `lp_share_meta_v22::LP_SHARE_URI_BASE_DEVNET` | `https://play.percolator.trade` |
| default (mainnet) | `lp_share_meta_v22::LP_SHARE_URI_BASE_MAINNET` | `https://percolator.trade` (**FOUNDER DECISION**: the builder's default; confirm before a mainnet build) |

* Both are pinned by the unit test `uri_bases_are_pinned`. `scripts/check-mainnet-sbf.sh`
  fails unless the mainnet base string is in the `.so` and the devnet one is not.
* **The domain is a permanent trust anchor.** Whoever controls it controls the name, image and
  link wallets show for every share token, and for ticker records it can never be changed.
  Holding the domain indefinitely is part of the decision.

### The JSON the app must serve (not built here)

`GET <BASE>/api/earn-share/<market>` -> `200`, `Content-Type: application/json`,
`Access-Control-Allow-Origin: *`, no authentication, cacheable (suggest
`Cache-Control: public, max-age=300`).

```json
{
  "name": "Percolator Earn BURNIE BeumQK",
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

* **Validate the path parameter**: it must decode as a 32-byte base58 public key, and the LP
  vault registry PDA `["lp_vault", market]` under the wrapper must exist and be owned by the
  wrapper; otherwise `404`. Never echo the raw parameter into the response.
* **Build the response from chain state, not from the app database**: `name` and `symbol` are
  read from the Metaplex record (PDA `["metadata", metaqbxx..., lp_vault_mint(market)]`, NUL
  padding trimmed), and only if that record's update authority is the registry PDA and its
  mint is the share mint. If there is no such record, return the generic form
  (`Percolator Earn Share <first 8>`, `pEARN`).
* `image`: `GET <BASE>/api/earn-share/<market>/image` -> a square PNG (512 x 512): the market
  token's logo with a Percolator badge in a corner; when the token has no logo, the Percolator
  mark alone. A stable URL (wallets cache by URL). The token logo is creator-supplied content:
  serve it re-encoded from our own origin, never as a redirect to a third-party URL.
* `external_url`: the market's Earn page, `<BASE>/earn/<market>`.
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
