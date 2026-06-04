param(
  [Parameter(Mandatory = $true)][string]$institution_type,
  [string]$branch_code = "001",
  [Parameter(Mandatory = $true)][int]$demo_seed_i32
)

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = "/tmp/cse-plus-public-target" }
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null
cargo run --quiet -p tuff-cse-cli -- install-local `
  --institution-type $institution_type `
  --branch-code $branch_code `
  --demo-seed-i32 $demo_seed_i32 `
  --output-root target/release-audit/installations
