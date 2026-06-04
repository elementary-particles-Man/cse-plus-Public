param()

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$denylist = @(
  'SilentNoOracle',
  'NoOracle',
  'KeyCseV3',
  'KeyCSE v3',
  'KmsSplit',
  'RuntimeTriplet',
  'BootstrapKey',
  'FacilityGeneratedKey',
  'MK',
  'TK',
  'PK',
  'M_part',
  'T_part',
  'P_part',
  'TRUE',
  'PITH'
)

$matches = @()
foreach ($term in $denylist) {
  $found = & rg -n -I -F $term $root --glob '!scripts/public_repo_audit.sh' --glob '!scripts/public_repo_audit.ps1' 2>$null
  if ($LASTEXITCODE -eq 0 -and $found) {
    $matches += $found
  }
}

if ($matches.Count -gt 0) {
  $matches | ForEach-Object { Write-Output $_ }
  Write-Error "Public repo audit failed"
  exit 1
}

Write-Output "Public repo audit passed"
