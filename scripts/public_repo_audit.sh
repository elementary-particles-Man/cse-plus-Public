#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
denylist=(
  'SilentNoOracle'
  'NoOracle'
  'KeyCseV3'
  'KeyCSE v3'
  'KmsSplit'
  'RuntimeTriplet'
  'BootstrapKey'
  'FacilityGeneratedKey'
  'MK'
  'TK'
  'PK'
  'M_part'
  'T_part'
  'P_part'
  'TRUE'
  'PITH'
)

matches=0
for term in "${denylist[@]}"; do
  while IFS= read -r path; do
    case "$path" in
      */scripts/public_repo_audit.sh|*/scripts/public_repo_audit.ps1) continue ;;
    esac
    printf '%s:%s\n' "$path" "$term"
    matches=1
  done < <(grep -R -n -I -F "$term" "$root" --exclude='public_repo_audit.sh' --exclude='public_repo_audit.ps1' || true)
done

if [ "$matches" -ne 0 ]; then
  echo "Public repo audit failed" >&2
  exit 1
fi

echo "Public repo audit passed"
