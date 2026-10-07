use percolator_prog::state;
#[test]
fn sec_account_lens() {
    eprintln!("LEN lp_redemption legacy {}", state::lp_redemption_account_len());
    eprintln!("LEN lp_redemption v22    {}", state::lp_redemption_v22_account_len());
    eprintln!("LEN lp_vault_registry    {}", state::lp_vault_registry_account_len());
    eprintln!("LEN vault_lp_state       {}", state::vault_lp_state_account_len());
    eprintln!("LEN vault_lp_ext         {}", state::vault_lp_ext_account_len());
    eprintln!("LEN nft_registry         {}", state::nft_registry_account_len());
    eprintln!("LEN backing_ledger       {}", state::backing_domain_ledger_account_len());
    eprintln!("LEN insurance_ledger     {}", state::insurance_ledger_account_len());
}
