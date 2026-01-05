Percolator security review (per high.cmd)

Verification Status

All 5 findings independently verified by Claude Opus 4.5 on 2026-01-05.

Finding 1: ✅ CONFIRMED
Finding 2: ✅ CONFIRMED
Finding 3: ✅ CONFIRMED
Finding 4: ✅ CONFIRMED
Finding 5: ✅ CONFIRMED
Scope + assumptions

Scope: percolator/ (engine), percolator-prog/ (Solana program wrapper), plus quick checks of matcher ABI glue.
Assumptions (from prompt): contract owners/admins are trusted; findings should not rely on malicious insiders/admin key compromise.
I did not implement fixes; this file documents issues and suggested remediations only.
Investigation log (approximate)

00:00–00:05: Read perc.md to understand architecture and trust boundaries (engine vs wrapper vs CPI matcher).
00:05–00:20: Enumerated instruction handlers in percolator-prog/src/percolator.rs, focusing on account validation, signer/writable checks, PDAs, token CPI usage, and oracle handling.
00:20–00:35: Reviewed oracle parsing/validation in percolator-prog/src/percolator.rs (mod oracle) and where oracle key checks are/aren’t applied per instruction.
00:35–00:55: Reviewed CPI matcher binding and ABI checks for obvious signer/CPI escape hatches.
00:55–01:25: Reviewed high-risk engine flows in percolator/src/percolator.rs (withdrawals, maintenance margin checks, funding, keeper crank) looking for economic extraction and margin-check inconsistencies.
01:25–01:40: Cross-referenced wrapper behavior vs engine assumptions (e.g., which instructions provide oracle/token program inputs, and whether wrapper constrains them).
01:40–01:55: Wrote up 5 critical/high findings with exploit sketches and file pointers.
Findings (5)

1) Critical: CloseAccount allows arbitrary CPI with PDA signer (token-program not validated)

Verification: ✅ CONFIRMED - Lines 2015-2060 show no verify_token_program(a_token)?; call. Compare to WithdrawCollateral (line 1632), DepositCollateral (line 1594), InitUser (line 1536), InitLP (line 1565), TopUpInsurance (line 2071) which ALL call verify_token_program(a_token)?;. Additionally, CloseAccount is missing verify_token_account(a_user_ata, a_user.key, &mint)?; which WithdrawCollateral has at line 1659.

Where

percolator-prog/src/percolator.rs:2015 (CloseAccount handler)
Missing verify_token_program(a_token) before collateral::withdraw(...) at percolator-prog/src/percolator.rs:2059
What / impact

CloseAccount accepts a a_token “token program” account but never checks it is spl_token::ID / executable.
The program then performs invoke_signed using the vault authority PDA as signer (via collateral::withdraw), but the CPI target program id comes from a_token.key.
A malicious caller can supply any executable program as a_token, causing your program to invoke attacker-controlled code with a PDA signer and writable vault+destination accounts.
Exploit sketch

Attacker deploys a malicious program M.
Attacker calls CloseAccount, passing a_token = M, and sets a_user_ata to an attacker-owned token account.
Inside M, ignore the incoming instruction data and perform one or more CPIs to spl_token::transfer moving more than the intended amt_u64 from a_vault to a_user_ata, using the provided PDA signer.
Result: vault drained to the attacker’s ATA (catastrophic loss of funds).
Why this works

The PDA signature is valid for any CPI invoked via invoke_signed, not only SPL Token.
The wrapper currently doesn’t constrain which program id receives that signed invocation in CloseAccount.
Suggested remediation

In CloseAccount, call verify_token_program(a_token) before any CPI.
Also validate a_user_ata is a real SPL token account with expected mint (mirroring WithdrawCollateral’s checks).
2) Critical: Permissionless KeeperCrank lets attacker choose funding rate (economic extraction / griefing)

Verification: ✅ CONFIRMED - Line 1699 shows permissionless mode when caller_idx == CRANK_NO_CALLER (u16::MAX). In this mode, line 1701-1704 skips signer check. Line 1733 passes user-supplied funding_rate_bps_per_slot directly to engine.keeper_crank(...) without any validation or derivation from oracle/on-chain state.

Where

percolator-prog/src/percolator.rs:1689 (KeeperCrank handler takes funding_rate_bps_per_slot from instruction data)
Engine uses that input directly: percolator/src/percolator.rs:1182 and percolator/src/percolator.rs:1751 (accrue_funding)
What / impact

In permissionless mode (caller_idx == u16::MAX), anyone can call KeeperCrank and supply an arbitrary funding_rate_bps_per_slot (bounded only by the engine’s hard cap at 100% per slot).
Funding is a value transfer mechanism between accounts; allowing an arbitrary public input here is equivalent to letting an attacker set a key economic parameter.
Exploit sketch

Attacker opens a position whose funding direction benefits from a chosen sign of funding.
Attacker repeatedly calls KeeperCrank permissionlessly with funding_rate_bps_per_slot = ±10_000 (or another extreme within the cap).
Funding index moves dramatically; accounts settle funding on touch/ops and PnL is redistributed according to attacker-controlled funding.
Why this works

The wrapper does not derive funding from any oracle or on-chain observable; it trusts the instruction input even in permissionless mode.
Suggested remediation

Remove funding_rate_bps_per_slot from the public instruction API, or require a trusted signer/oracle-derived mechanism.
If you need permissionless cranks, make funding rate a function of on-chain state (or set by admin with rate limits), not arbitrary caller input.
3) Critical: Permissionless KeeperCrank does not validate oracle key (oracle substitution → forced liquidations/panic actions)

Verification: ✅ CONFIRMED - Line 1728 calls oracle::read_pyth_price_e6(a_oracle, ...) without any prior key validation. No oracle_key_ok(config.index_oracle, a_oracle.key.to_bytes()) check exists. Compare to TradeCpi (lines 1907-1910) and WithdrawCollateral (lines 1650-1653) which DO validate oracle key.

Where

percolator-prog/src/percolator.rs:1689 (KeeperCrank)
Reads price directly from a_oracle without checking it matches config.index_oracle: percolator-prog/src/percolator.rs:1728
What / impact

Any caller can run KeeperCrank with an arbitrary Pyth price account (owner-checked in oracle::read_pyth_price_e6, but not key-checked against market config).
keeper_crank runs liquidation scans and may trigger heavy actions (force_realize_losses, panic_settle_all) using the supplied oracle price.
This allows griefing and/or forced liquidations using a wrong price feed.
Exploit sketch

Attacker selects a Pyth feed with an extreme price (too low or too high vs the market’s index).
Calls KeeperCrank permissionlessly supplying that oracle.
Engine’s liquidation scan uses the attacker-chosen price (percolator/src/percolator.rs:1227–1230), liquidating accounts that should not be liquidated (or skipping ones that should).
Suggested remediation

Add oracle_key_ok(config.index_oracle, a_oracle.key) validation in KeeperCrank (like WithdrawCollateral / TradeCpi already do).
4) High/Critical: LiquidateAtOracle does not validate oracle key (oracle substitution → wrongful liquidations)

Verification: ✅ CONFIRMED - Lines 2010-2011 show oracle::read_pyth_price_e6(&accounts[3], ...) is called without any preceding key validation. No oracle_key_ok(config.index_oracle, ...) check exists anywhere in the LiquidateAtOracle handler (lines 1996-2014).

Where

percolator-prog/src/percolator.rs:1996 (LiquidateAtOracle handler)
No oracle_key_ok check before oracle::read_pyth_price_e6(...) at percolator-prog/src/percolator.rs:2010–2013
What / impact

Liquidation is permissionless and uses a caller-supplied oracle account.
Without validating the oracle account matches the market’s configured oracle pubkey, an attacker can liquidate using the “wrong” price feed.
Even if liquidator does not receive a direct reward, this is still high severity as it enables targeted griefing and can force fee extraction into insurance at arbitrary times/prices.
Suggested remediation

Require oracle_key_ok(config.index_oracle, provided_oracle.key) in this instruction.
5) High/Critical: Engine withdrawal margin check uses entry_price and doesn't re-check maintenance margin after withdrawing

Verification: ✅ CONFIRMED - Lines 1978-1981 compute position_notional using account.entry_price instead of oracle_price. Line 1960 calls touch_account_full (maintenance check) BEFORE the withdrawal. Lines 1991-1993 commit the withdrawal. No maintenance margin re-check occurs after. Compare to is_above_margin_bps (lines 2032-2044) which correctly uses oracle_price for margin calculations.

Where

percolator/src/percolator.rs:1941 (withdraw)
Uses account.entry_price (not oracle_price) for initial margin notional: percolator/src/percolator.rs:1976–1989
Maintenance margin is checked before reducing capital (inside touch_account_full), but not after the withdrawal is applied.
What / impact

Withdrawal should ensure the post-withdrawal account remains adequately margined at current prices.
Current logic can allow a user to withdraw to a state where:
post-withdraw equity passes the (entry-price-based) initial margin check, but
post-withdraw equity is below maintenance margin at the current oracle price (because no maintenance re-check occurs after debiting capital).
This enables users to extract collateral while leaving an immediately-liquidatable position, increasing bad-debt risk and socialized losses.
Concrete scenario

Suppose initial_margin_bps / maintenance_margin_bps = 2 (e.g., 10% vs 5%).
If price has moved >2× since entry, maintenance margin at current oracle can exceed initial margin computed from entry.
A user can withdraw down to just above the entry-based initial margin, ending below maintenance at current price.
Suggested remediation

Compute notional for withdrawal checks using oracle_price (or a conservative function of oracle_price and entry_price, depending on desired risk posture).
After applying the withdrawal (capital reduction), re-check maintenance margin (and/or initial margin) at oracle_price on the updated state before committing.
Notes / things I checked that didn’t become findings

Slab ownership/length checks (slab_guard) look correct and consistently applied where state is mutated.
TradeCpi matcher binding (program+context identity) and ABI echo checks appear intentionally strict.
WithdrawCollateral validates oracle key and vault authority PDA; deposit/withdraw token flows appear ordered to rely on Solana instruction atomicity.
Pages 2

Home
AUDIT
Percolator security review (per high.cmd)
Verification Status
Scope + assumptions
Investigation log (approximate)
Findings (5)
1) Critical: CloseAccount allows arbitrary CPI with PDA signer (token-program not validated)
2) Critical: Permissionless KeeperCrank lets attacker choose funding rate (economic extraction / griefing)
3) Critical: Permissionless KeeperCrank does not validate oracle key (oracle substitution → forced liquidations/panic actions)
4) High/Critical: LiquidateAtOracle does not validate oracle key (oracle substitution → wrongful liquidations)
5) High/Critical: Engine withdrawal margin check uses entry_price and doesn't re-check maintenance margin after withdrawing
Notes / things I checked that didn’t become findings
Clone this wiki locally

	
Footer

