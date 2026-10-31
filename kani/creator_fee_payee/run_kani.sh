#!/usr/bin/env bash
# prog#587: run every harness once on the production file. Local only (never in CI).
set -euo pipefail
cd "$(dirname "$0")"
exec cargo kani -j 2 --output-format terse
