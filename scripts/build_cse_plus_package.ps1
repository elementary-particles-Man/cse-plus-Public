param()

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = "/tmp/cse-plus-public-target" }
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null
New-Item -ItemType Directory -Force -Path target/release-audit/packages | Out-Null
cargo build --bin cse_txn
cargo build --release --bin cse_txn
cargo run --quiet -p tuff-cse-cli -- package-local --output-root target/release-audit/packages
