#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cse-plus-public-target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo run --quiet -p tuff-cse-cli -- prepare-three-bank-local --output-root target/release-audit/three-bank-local
