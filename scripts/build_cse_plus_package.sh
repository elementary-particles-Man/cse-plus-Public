#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cse-plus-public-target}"
mkdir -p "$CARGO_TARGET_DIR"
mkdir -p target/release-audit/packages
cargo build --bin cse_txn
cargo build --release --bin cse_txn
cargo run --quiet -p tuff-cse-cli -- package-local --output-root target/release-audit/packages
