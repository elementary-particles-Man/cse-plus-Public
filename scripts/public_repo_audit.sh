#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required_files=(
  "README.md"
  "Cargo.toml"
  "crates/cse-plus-standard/Cargo.toml"
)

for file in "${required_files[@]}"; do
  if [ ! -f "$root/$file" ]; then
    printf 'missing required file: %s\n' "$file" >&2
    exit 1
  fi
done

if ! grep -q '^# CSE\+' "$root/README.md"; then
  echo "README does not describe the public CSE+ line" >&2
  exit 1
fi

echo "Public repo audit passed"
