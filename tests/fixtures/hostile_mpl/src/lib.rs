//! TEST FIXTURE, never deployed: a hostile stand-in mounted AT THE METAPLEX PROGRAM ID in
//! LiteSVM, to model a malicious upgrade of the Token Metadata program receiving tag 122's
//! create CPI (prog#545 security review round 2, F1; written by the reviewer, ported as is).
//!
//! It ignores the instruction data and attacks whatever it was handed as the PAYER
//! (`accounts[3]` of `CreateMetadataAccountV3`), using the payer's signature:
//!
//! mode = lamports of `accounts[0]` (the metadata PDA, pre-funded by the test) % 10
//!   1  assign the payer to this program
//!   2  take everything, then assign the payer to this program
//!   3  allocate 8 bytes of data on the payer
//!   4  take everything
//!   5  take all but 1,000,000 lamports, then assign the payer to this program
//!   *  do nothing
//!
//! Build: `scripts/build-hostile-mpl.sh` (output `tests/fixtures/hostile_mpl/target/deploy/hostile_mpl.so`).
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program::invoke,
    pubkey::Pubkey, system_instruction,
};
entrypoint!(process);
fn process(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let metadata = &accounts[0];
    let payer = &accounts[3];
    let system = &accounts[5];
    let mode = metadata.lamports() % 10;
    let all = payer.lamports();
    match mode {
        1 => invoke(&system_instruction::assign(payer.key, program_id), &[payer.clone(), system.clone()])?,
        2 => {
            invoke(&system_instruction::transfer(payer.key, metadata.key, all), &[payer.clone(), metadata.clone(), system.clone()])?;
            invoke(&system_instruction::assign(payer.key, program_id), &[payer.clone(), system.clone()])?;
        }
        3 => invoke(&system_instruction::allocate(payer.key, 8), &[payer.clone(), system.clone()])?,
        4 => invoke(&system_instruction::transfer(payer.key, metadata.key, all), &[payer.clone(), metadata.clone(), system.clone()])?,
        // 5: leave a balance on a PDA re-assigned to this program
        5 => {
            invoke(&system_instruction::transfer(payer.key, metadata.key, all - 1_000_000), &[payer.clone(), metadata.clone(), system.clone()])?;
            invoke(&system_instruction::assign(payer.key, program_id), &[payer.clone(), system.clone()])?;
        }
        _ => {}
    }
    Ok(())
}
