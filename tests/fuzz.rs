use proptest::prelude::*;
use percolator_prog::ix::Instruction;

proptest! {
    #[test]
    fn fuzz_instruction_decode(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        // Just verify it doesn't panic
        let _ = Instruction::decode(&data);
    }
}
