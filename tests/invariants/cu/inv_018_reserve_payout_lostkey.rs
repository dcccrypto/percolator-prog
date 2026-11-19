//! INV-018, reserve payouts: the lost-key exception, pinned (#477).
//!
//! Upstream 0b06131f leaves reserve payouts (`WithdrawBackingBucket`,
//! `WithdrawBackingBucketEarnings`, a resolved-market backing payout) payable in either
//! mint without the beneficiary's signature, so that a beneficiary that has dropped its
//! key stays payable. This test pins that behaviour and its consequence: the market
//! authority (`marketauth`) signs the call, the beneficiary is paid in the secondary mint,
//! and the primary tokens it displaced are surplus that `CloseSlab` pays to `marketauth`.
//! See docs/security/477-lostkey-finding.md.

use super::*;

const RESERVE: u64 = 100;

#[test]
fn v16_inv018_lostkey_backing_payout_is_either_mint_pinned() {
    let mut env = V16CuEnv::new();
    let secondary = env.create_mint();
    env.update_base_unit_mints_with_cu(env.mint, secondary);
    let insurance_authority = Keypair::new();
    let insurance_operator = Keypair::new();
    let beneficiary = Keypair::new();
    env.activate_asset_with_authorities(
        1,
        1,
        100,
        insurance_authority.pubkey(),
        insurance_operator.pubkey(),
        beneficiary.pubkey(),
        env.admin.pubkey(),
    );
    let ledger = env.canonical_backing_domain_ledger_account(2);
    // The backing authority funds the bucket with its signature, then drops its key.
    env.ensure_signer_account(beneficiary.pubkey());
    let source = Pubkey::new_unique();
    env.svm
        .set_account(
            source,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, beneficiary.pubkey(), RESERVE),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let top_up_epoch = env.backing_withdraw_authority_epoch(2, &beneficiary.pubkey());
    let top_up_market_id = state::read_market_trade_preflight(
        &env.svm.get_account(&env.market).unwrap().data,
        1,
    )
    .unwrap()
    .3;
    send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::TopUpBackingBucket {
            intent_id: next_intent_id(),
            market_id: top_up_market_id,
            domain: 2,
            amount: RESERVE as u128,
            expiry_slot: 10,
            authority_epoch: top_up_epoch,
        },
        vec![
            AccountMeta::new(beneficiary.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(source, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&beneficiary],
    )
    .expect("the backing authority funds the bucket");
    assert_eq!(env.token_amount(env.vault), RESERVE);
    env.resolve();
    // The secondary vault holds what anyone sent to it.
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
    let beneficiary_secondary = env.token_account_for_mint(secondary, beneficiary.pubkey(), 0);

    // `marketauth` signs; the beneficiary does not.
    let admin = env.admin.insecure_clone();
    let authority_epoch = env.backing_withdraw_authority_epoch(2, &admin.pubkey());
    let market_id = state::read_market_trade_preflight(
        &env.svm.get_account(&env.market).unwrap().data,
        1,
    )
    .unwrap()
    .3;
    env.svm.expire_blockhash();
    send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket {
            market_id,
            domain: 2,
            amount: RESERVE as u128,
            authority_epoch,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(beneficiary_secondary, false),
            AccountMeta::new(secondary_vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&admin],
    )
    .expect("a resolved reserve payout in the secondary mint is accepted (lost-key exception)");
    let balances = (
        env.token_amount(beneficiary_secondary),
        env.token_amount(secondary_vault),
        env.token_amount(env.vault),
    );
    println!("after payout: beneficiary(secondary)={} secondary_vault={} primary_vault={}", balances.0, balances.1, balances.2);
    assert_eq!(balances, (RESERVE, 0, RESERVE));

    // `CloseSlab` pays the displaced primary tokens to `marketauth`.
    let primary_dest = env.token_account_for_mint(env.mint, admin.pubkey(), 0);
    let secondary_dest = env.token_account_for_mint(secondary, admin.pubkey(), 0);
    for _ in 0..8 {
        env.svm.expire_blockhash();
        let authority_epoch = env.control_sequences(0).authority_epoch;
        send_tx(
            &mut env.svm,
            env.program_id,
            &env.payer,
            ProgInstruction::CloseSlab { authority_epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(env.vault_authority, false),
                AccountMeta::new(primary_dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(secondary_vault, false),
                AccountMeta::new(secondary_dest, false),
                AccountMeta::new(env.mint, false),
            ],
            &[&admin],
        )
        .expect("CloseSlab");
        let closed = env
            .svm
            .get_account(&env.market)
            .map_or(true, |m| m.data.len() <= percolator_prog::constants::HEADER_LEN);
        if closed {
            break;
        }
    }
    println!(
        "after CloseSlab: marketauth primary={} secondary={}",
        env.token_amount(primary_dest),
        env.token_amount(secondary_dest)
    );
    assert_eq!(env.token_amount(primary_dest), RESERVE, "marketauth receives the displaced primary tokens");
}
