#!/usr/bin/env bash
set -euo pipefail

institution_type=""
branch_code="001"
demo_seed_i32=""

while [ $# -gt 0 ]; do
  case "$1" in
    --institution-type)
      institution_type="${2:-}"
      shift 2
      ;;
    --branch-code)
      branch_code="${2:-}"
      shift 2
      ;;
    --demo-seed-i32)
      demo_seed_i32="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$institution_type" ] || [ -z "$demo_seed_i32" ]; then
  echo "--institution-type and --demo-seed-i32 are required" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cse-plus-public-target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo run --quiet -p tuff-cse-cli -- install-local \
  --institution-type "$institution_type" \
  --branch-code "$branch_code" \
  --demo-seed-i32 "$demo_seed_i32" \
  --output-root target/release-audit/installations
