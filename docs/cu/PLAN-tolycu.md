Plan: read_market_trade_preflight (src/v16_program.rs ~2787) and read_asset_effective_prices (~2818) decode
the market config with try_to_runtime() (full solvency-envelope check) but only read max_market_slots,
max_portfolio_assets, max_trading_fee_bps. Switch both to try_to_runtime_shape().

Config writers at add1d027:
- handle_init_market -> init_market_account_zero_copy -> MarketGroupV16HeaderAccount::new_dynamic: validate_public_user_fund() (full).
- slot grow: wrapper reads try_to_runtime() (full) first, then engine grow_asset_slot_capacity_not_atomic
  changes only max_market_slots and re-checks shape; validate_exact_solvency_envelope does not read max_market_slots/max_portfolio_assets.
- fee updates (handle_update_trade_fee_policy / backing fee policy) edit WrapperConfigV16 only, not the engine config.
- write_market_wire (cfg not solana): host-only test helper from a runtime group.
No writer skips the check. Proceed.
