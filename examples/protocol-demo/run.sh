#!/usr/bin/env bash
# Runnable end-to-end SUDP protocol demo.
# Builds the three packages, spawns the Rust Custodian, runs the Node
# script that plays the Requester and Authorizer roles, prints annotated
# output of every wire interaction, and tears down cleanly.

set -euo pipefail

cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"

# ── Toolchain sanity check ─────────────────────────────────────────────
need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: '$1' not found in PATH." >&2
    echo "       $2" >&2
    exit 1
  }
}
need cargo "Install Rust via rustup: https://rustup.rs"
need npm   "Install Node.js (includes npm): https://nodejs.org (>=20)"

echo "== Building @sudp/authorizer (TS)"
(cd "$REPO/authorizer/ts" && npm install --silent && npm run --silent build)

echo "== Building @sudp/requester (TS)"
(cd "$REPO/requester/ts" && npm install --silent && npm run --silent build)

echo "== Building sudp-demo-custodian (Rust, release)"
(cd custodian && cargo build --release --quiet)

echo "== Installing demo runner deps"
(cd runner && npm install --silent)

echo "== Running demo"
echo
cd runner && npm start --silent
