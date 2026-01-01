#[cfg(kani)]
mod verification {
    use percolator_prog::ix::Instruction;

    #[kani::proof]
    fn verify_instruction_decode_no_panic() {
        let input_len: usize = kani::any();
        // Limit length to reasonable instruction size for efficient verification
        // 256 bytes is enough to cover all instruction variants
        kani::assume(input_len <= 256); 
        
        let mut input = [0u8; 256];
        for i in 0..256 {
            if i < input_len {
                input[i] = kani::any();
            }
        }
        
        let _ = Instruction::decode(&input[..input_len]);
    }
}
