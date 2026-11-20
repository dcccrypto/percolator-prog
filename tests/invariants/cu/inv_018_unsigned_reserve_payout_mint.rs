//! INV-018, reserve payouts: a reserve claim is paid in the secondary mint only with its
//! payee's signature (#477, port of upstream 048085cf).
//!
//! After resolution anyone can deliver a backing bucket (`WithdrawBackingBucket`), an
//! insurance budget (`WithdrawInsuranceAsset`) or the terminal insurance reserve
//! (`WithdrawInsurance`, tag 41, v2.2 only) to a token account its payee owns. `marketauth`
//! names the secondary mint and anyone can fund its vault, so a delivery the payee did not
//! sign is made in the deposit mint: otherwise the payee would be paid in a mint of the
//! authority's making while what it paid in stayed in the primary vault for `CloseSlab`.
//! A payee that lost its key is still paid, unsigned, in the primary mint.
//!
//! `WithdrawInsuranceAsset` is Live-only and signed in this tree; only its signed case is
//! tested. Its non-payee route (marketauth's shutdown drain when insurance_authority is zero)
//! now also requires the primary mint, but no fixture covers that route here.
//!
//! Replaces `inv_018_reserve_payout_lostkey.rs` (#756), which pinned the opposite behaviour
//! on 0b06131f. Upstream's ClosePortfolio half of 048085cf is not ported: this tree already
//! lets anyone remove an empty resolved portfolio (Sieve F-4, #377).

use super::*;

const RESERVE: u64 = 100;

#[derive(Clone, Copy, Debug)]
enum Rail {
    Backing,
    InsuranceAsset,
    TerminalInsurance,
}

struct Fixture {
    env: V16CuEnv,
    payee: Keypair,
    rail: Rail,
    secondary: Pubkey,
    secondary_vault: Pubkey,
}

fn is_invalid_mint_error(error: &str) -> bool {
    error.contains(&format!("Custom({})", PercolatorError::InvalidMint as u32))
}

/// A third party holds the payee role of asset 1 on `rail` and funds it in the deposit mint.
/// The market authority names a secondary mint and the secondary vault holds `RESERVE`. The
/// market is resolved and has no portfolios.
fn resolved_reserve(rail: Rail) -> Fixture {
    let mut env = V16CuEnv::new();
    let secondary = env.create_mint();
    env.update_base_unit_mints_with_cu(env.mint, secondary);
    let insurance_authority = Keypair::new();
    let insurance_operator = Keypair::new();
    let backing_authority = Keypair::new();
    env.activate_asset_with_authorities(
        1,
        1,
        100,
        insurance_authority.pubkey(),
        insurance_operator.pubkey(),
        backing_authority.pubkey(),
        env.admin.pubkey(),
    );
    let payee = match rail {
        Rail::Backing => {
            env.ensure_signer_account(backing_authority.pubkey());
            let ledger = env.canonical_backing_domain_ledger_account(2);
            let source = Pubkey::new_unique();
            env.svm
                .set_account(
                    source,
                    Account {
                        lamports: 1_000_000_000,
                        data: make_token_data(env.mint, backing_authority.pubkey(), RESERVE),
                        owner: spl_token::ID,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            let authority_epoch =
                env.backing_withdraw_authority_epoch(2, &backing_authority.pubkey());
            let market_id = asset_market_id(&env, 1);
            send_tx(
                &mut env.svm,
                env.program_id,
                &env.payer,
                ProgInstruction::TopUpBackingBucket {
                    intent_id: next_intent_id(),
                    market_id,
                    domain: 2,
                    amount: RESERVE as u128,
                    expiry_slot: 10,
                    authority_epoch,
                },
                vec![
                    AccountMeta::new(backing_authority.pubkey(), true),
                    AccountMeta::new(env.market, false),
                    AccountMeta::new(source, false),
                    AccountMeta::new(env.vault, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new(ledger, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                ],
                &[&backing_authority],
            )
            .expect("the backing authority funds the bucket");
            backing_authority
        }
        Rail::InsuranceAsset => {
            env.top_up_insurance_domain_with_authority(&insurance_authority, 2, RESERVE.into());
            // The domain withdrawal pays the recorded insurance_operator.
            insurance_operator
        }
        Rail::TerminalInsurance => {
            env.top_up_insurance_domain_with_authority(&insurance_authority, 2, RESERVE.into());
            insurance_authority
        }
    };
    assert_eq!(env.token_amount(env.vault), RESERVE);
    // `WithdrawInsuranceAsset` is Live-only here and always signed (the resolved insurance
    // payout is tag 41), so its rail stays Live.
    if !matches!(rail, Rail::InsuranceAsset) {
        env.resolve();
    }
    env.ensure_signer_account(payee.pubkey());
    let secondary_vault = canonical_vault_ata(&env.vault_authority, &secondary);
    env.svm
        .set_account(
            secondary_vault,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(secondary, env.vault_authority, RESERVE),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    Fixture { env, payee, rail, secondary, secondary_vault }
}

fn asset_market_id(env: &V16CuEnv, asset_index: usize) -> u64 {
    state::read_market_trade_preflight(&env.svm.get_account(&env.market).unwrap().data, asset_index)
        .unwrap()
        .3
}

impl Fixture {
    /// The payout of the payee's whole reserve to `dest` from `vault`, signed by the payee
    /// only when `signed` (otherwise the fee payer submits it alone).
    fn pay(&mut self, dest: Pubkey, vault: Pubkey, signed: bool) -> Result<u64, String> {
        let payee = self.payee.insecure_clone();
        let mut accounts = vec![
            AccountMeta::new_readonly(payee.pubkey(), signed),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(self.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        let ix = match self.rail {
            Rail::Backing => {
                accounts.push(AccountMeta::new(
                    self.env.canonical_backing_domain_ledger_account(2),
                    false,
                ));
                ProgInstruction::WithdrawBackingBucket {
                    market_id: asset_market_id(&self.env, 1),
                    domain: 2,
                    amount: RESERVE as u128,
                    authority_epoch: self.env.backing_withdraw_authority_epoch(2, &payee.pubkey()),
                }
            }
            Rail::InsuranceAsset => ProgInstruction::WithdrawInsuranceAsset {
                market_id: asset_market_id(&self.env, 1),
                asset_index: 1,
                amount: RESERVE as u128,
                authority_epoch: self.env.insurance_withdraw_authority_epoch(1, &payee.pubkey()),
            },
            Rail::TerminalInsurance => {
                ProgInstruction::WithdrawInsurance { amount: RESERVE as u128 }
            }
        };
        self.env.svm.expire_blockhash();
        let signers: Vec<&Keypair> = if signed { vec![&payee] } else { vec![] };
        send_tx(&mut self.env.svm, self.env.program_id, &self.env.payer, ix, accounts, &signers)
    }

    fn balances(&self, dest: Pubkey) -> (u64, u64, u64) {
        (
            self.env.token_amount(dest),
            self.env.token_amount(self.secondary_vault),
            self.env.token_amount(self.env.vault),
        )
    }
}

/// Unsigned, a delivery in the secondary mint is refused with nothing changed; the same
/// delivery in the deposit mint is accepted, so a payee without its key is still paid.
fn unsigned_payout_is_primary_mint(rail: Rail) {
    let mut f = resolved_reserve(rail);
    let payee = f.payee.pubkey();
    let dest_secondary = f.env.token_account_for_mint(f.secondary, payee, 0);
    let frame_before = (
        f.env.svm.get_account(&f.env.market),
        f.balances(dest_secondary),
    );
    let error = f
        .pay(dest_secondary, f.secondary_vault, false)
        .expect_err("an unsigned reserve payout in the secondary mint is refused");
    assert!(is_invalid_mint_error(&error), "{rail:?}: expected InvalidMint, got {error}");
    assert_eq!(
        (f.env.svm.get_account(&f.env.market), f.balances(dest_secondary)),
        frame_before,
        "{rail:?}: the refused payout changes nothing"
    );

    let dest_primary = f.env.token_account_for_mint(f.env.mint, payee, 0);
    let vault = f.env.vault;
    f.pay(dest_primary, vault, false)
        .unwrap_or_else(|e| panic!("{rail:?}: the unsigned primary-mint payout is accepted: {e}"));
    assert_eq!(f.balances(dest_primary), (RESERVE, RESERVE, 0), "{rail:?}");
}

/// With its own signature the payee takes the secondary mint.
fn signed_payee_may_take_secondary_mint(rail: Rail) {
    let mut f = resolved_reserve(rail);
    let payee = f.payee.pubkey();
    let dest_secondary = f.env.token_account_for_mint(f.secondary, payee, 0);
    f.pay(dest_secondary, f.secondary_vault, true)
        .unwrap_or_else(|e| panic!("{rail:?}: the signed secondary-mint payout is accepted: {e}"));
    assert_eq!(f.balances(dest_secondary), (RESERVE, 0, RESERVE), "{rail:?}");
}

#[test]
fn v16_inv018_unsigned_backing_payout_is_primary_mint() {
    unsigned_payout_is_primary_mint(Rail::Backing);
}

#[test]
fn v16_inv018_unsigned_terminal_insurance_payout_is_primary_mint() {
    unsigned_payout_is_primary_mint(Rail::TerminalInsurance);
}

#[test]
fn v16_inv018_signed_backing_payee_may_take_secondary_mint() {
    signed_payee_may_take_secondary_mint(Rail::Backing);
}

#[test]
fn v16_inv018_signed_insurance_asset_payee_may_take_secondary_mint() {
    signed_payee_may_take_secondary_mint(Rail::InsuranceAsset);
}

#[test]
fn v16_inv018_signed_terminal_insurance_payee_may_take_secondary_mint() {
    signed_payee_may_take_secondary_mint(Rail::TerminalInsurance);
}

/// The #756 finding, closed: the unsigned secondary payout no longer goes through, so
/// `CloseSlab` has no displaced primary tokens to pay `marketauth`. After the payee is paid
/// unsigned in the deposit mint, marketauth's primary share is 0 and the secondary vault's
/// own balance goes back to it in the secondary mint.
#[test]
fn v16_inv018_close_slab_gets_no_displaced_primary_after_reserve_payout() {
    let mut f = resolved_reserve(Rail::Backing);
    let payee = f.payee.pubkey();
    let dest_secondary = f.env.token_account_for_mint(f.secondary, payee, 0);
    assert!(f.pay(dest_secondary, f.secondary_vault, false).is_err());
    let dest_primary = f.env.token_account_for_mint(f.env.mint, payee, 0);
    let vault = f.env.vault;
    f.pay(dest_primary, vault, false).expect("unsigned primary payout");

    let admin = f.env.admin.insecure_clone();
    let primary_dest = f.env.token_account_for_mint(f.env.mint, admin.pubkey(), 0);
    let secondary_dest = f.env.token_account_for_mint(f.secondary, admin.pubkey(), 0);
    let mut closed = false;
    for _ in 0..8 {
        f.env.svm.expire_blockhash();
        let authority_epoch = f.env.control_sequences(0).authority_epoch;
        send_tx(
            &mut f.env.svm,
            f.env.program_id,
            &f.env.payer,
            ProgInstruction::CloseSlab { authority_epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(f.env.market, false),
                AccountMeta::new(f.env.vault, false),
                AccountMeta::new_readonly(f.env.vault_authority, false),
                AccountMeta::new(primary_dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(f.secondary_vault, false),
                AccountMeta::new(secondary_dest, false),
                AccountMeta::new(f.env.mint, false),
            ],
            &[&admin],
        )
        .expect("CloseSlab");
        closed = f
            .env
            .svm
            .get_account(&f.env.market)
            .map_or(true, |m| m.data.len() <= percolator_prog::constants::HEADER_LEN);
        if closed {
            break;
        }
    }
    assert!(closed, "CloseSlab finishes");
    assert_eq!(f.env.token_amount(dest_primary), RESERVE, "the payee keeps its deposit-mint claim");
    assert_eq!(f.env.token_amount(primary_dest), 0, "marketauth gets no displaced primary tokens");
    assert_eq!(f.env.token_amount(secondary_dest), RESERVE, "the secondary vault's own balance");
}
