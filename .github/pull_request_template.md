## Summary

<!-- What changed and why -->

## How to test

<!-- Steps to verify (build locally, LiteSVM tests, etc.) -->

## Checklist

- [ ] Build passes (`cargo build --lib`)
- [ ] Clippy clean (`cargo clippy --lib -- -W clippy::all`)
- [ ] Format check (`cargo fmt --check`)
- [ ] **If this PR touches math, proof logic, or invariant code**: run Kani locally before merging
  ```bash
  # One-time setup
  cargo install --locked kani-verifier && cargo kani setup
  # Run relevant harnesses
  cargo kani --tests --harness proof_
  ```
  Kani is **not** run automatically on every PR. Use the [Kani (Manual)](../../actions/workflows/kani-manual.yml) workflow for on-demand runs.

## Related

<!-- Task ID, issue, or PR -->
