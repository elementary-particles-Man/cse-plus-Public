param()

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$requiredFiles = @(
  'README.md',
  'Cargo.toml',
  'crates/cse-plus-standard/Cargo.toml'
)

foreach ($file in $requiredFiles) {
  if (-not (Test-Path (Join-Path $root $file))) {
    Write-Error ("missing required file: {0}" -f $file)
    exit 1
  }
}

$readme = Get-Content (Join-Path $root 'README.md') -Raw
if ($readme -notmatch '^# CSE\+') {
  Write-Error 'README does not describe the public CSE+ line'
  exit 1
}

Write-Output 'Public repo audit passed'
