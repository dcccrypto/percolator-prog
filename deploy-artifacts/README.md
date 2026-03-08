# deploy-artifacts/

This directory is reserved for reference notes about deployed program addresses and versions.

## ⚠️ Do NOT commit .so files here

Compiled Solana program binaries (`.so`) are ignored by `.gitignore` and must **never** be committed to source control.

**Why:** Committed binaries cannot be diffed for security review, and a future operator may mistakenly deploy from here instead of building from source.

**Correct deploy flow:**

```bash
# Always build from source first
./scripts/rebuild-deploy-devnet.sh
# Deploys from: target/deploy/percolator_prog.so
```

Binary artifacts in this directory are build-time outputs — add them to your local `.gitignore` exception or just delete them after each build.
