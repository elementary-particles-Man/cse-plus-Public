param()

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = "/tmp/cse-plus-public-target" }
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null
cargo run --quiet -p tuff-cse-cli -- prepare-three-bank-local --output-root target/release-audit/three-bank-local
