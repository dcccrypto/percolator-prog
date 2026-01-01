#[cfg(test)]
mod tests {
    use percolator_prog::ix::Instruction;
    use percolator::RiskParams;
    use solana_program::pubkey::Pubkey;

    fn encode_u64(val: u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn encode_u16(val: u16, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn encode_u8(val: u8, buf: &mut Vec<u8>) {
        buf.push(val);
    }
    fn encode_i64(val: i64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn encode_i128(val: i128, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn encode_u128(val: u128, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&val.to_le_bytes());
    }
    fn encode_pubkey(val: &Pubkey, buf: &mut Vec<u8>) {
        buf.extend_from_slice(val.as_ref());
    }

    #[test]
    fn test_decode_init_market() {
        let mut data = vec![0u8]; // Tag 0
        let admin = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        encode_pubkey(&admin, &mut data);
        encode_pubkey(&mint, &mut data);
        encode_pubkey(&Pubkey::new_unique(), &mut data); // pyth_index
        encode_pubkey(&Pubkey::new_unique(), &mut data); // pyth_collateral
        encode_u64(100, &mut data); // max_staleness
        encode_u16(500, &mut data); // conf_filter_bps
        
        // Risk Params (13 fields)
        encode_u64(1, &mut data);
        encode_u64(2, &mut data);
        encode_u64(3, &mut data);
        encode_u64(4, &mut data);
        encode_u64(5, &mut data);
        encode_u128(6, &mut data);
        encode_u128(7, &mut data);
        encode_u128(8, &mut data);
        encode_u64(9, &mut data);
        encode_u64(10, &mut data);
        encode_u128(11, &mut data);
        encode_u64(12, &mut data);
        encode_u128(13, &mut data);

        let ix = Instruction::decode(&data).unwrap();
        match ix {
            Instruction::InitMarket { admin: a, collateral_mint: m, risk_params: p, .. } => {
                assert_eq!(a, admin);
                assert_eq!(m, mint);
                assert_eq!(p.warmup_period_slots, 1);
                assert_eq!(p.min_liquidation_abs, 13);
            },
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_decode_init_user() {
        let mut data = vec![1u8]; // Tag 1
        encode_u64(12345, &mut data);
        let ix = Instruction::decode(&data).unwrap();
        match ix {
            Instruction::InitUser { fee_payment } => assert_eq!(fee_payment, 12345),
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_decode_trade_no_cpi() {
        let mut data = vec![6u8]; // Tag 6
        encode_u16(1, &mut data); // lp
        encode_u16(2, &mut data); // user
        encode_i128(-500, &mut data); // size
        let ix = Instruction::decode(&data).unwrap();
        match ix {
            Instruction::TradeNoCpi { lp_idx, user_idx, size } => {
                assert_eq!(lp_idx, 1);
                assert_eq!(user_idx, 2);
                assert_eq!(size, -500);
            },
            _ => panic!("Wrong instruction type"),
        }
    }

    #[test]
    fn test_decode_keeper_crank() {
        let mut data = vec![5u8]; // Tag 5
        encode_u16(10, &mut data); // caller
        encode_i64(-50, &mut data); // funding rate
        encode_u8(1, &mut data); // panic
        let ix = Instruction::decode(&data).unwrap();
        match ix {
            Instruction::KeeperCrank { caller_idx, funding_rate_bps_per_slot, allow_panic } => {
                assert_eq!(caller_idx, 10);
                assert_eq!(funding_rate_bps_per_slot, -50);
                assert_eq!(allow_panic, 1);
            },
            _ => panic!("Wrong instruction type"),
        }
    }
}
