#!/usr/bin/env bash
set -euo pipefail

institution_branch_id=""

while [ $# -gt 0 ]; do
  case "$1" in
    --institution-branch-id)
      institution_branch_id="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$institution_branch_id" ]; then
  echo "--institution-branch-id is required" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cse-plus-public-target}"
mkdir -p "$CARGO_TARGET_DIR"
cargo run --quiet -p tuff-cse-cli -- uninstall-local \
  --institution-branch-id "$institution_branch_id" \
  --output-root target/release-audit/installations
