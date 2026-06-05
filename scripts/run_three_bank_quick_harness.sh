#!/usr/bin/env bash
set -euo pipefail

iterations="10"

while [ $# -gt 0 ]; do
  case "$1" in
    --iterations)
      iterations="${2:-10}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cse-plus-public-target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo run --quiet -p tuff-cse-cli -- run-three-bank-quick-harness \
  --iterations "$iterations" \
  --topology-root target/release-audit/three-bank-local \
  --output-root target/release-audit/test-results
