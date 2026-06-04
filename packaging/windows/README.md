# Windows Local Package

The Windows package is a local zip artifact produced for install testing.

When the package flow runs on Linux, it may emit dry-run metadata instead of a
zip archive. On Windows, the package flow should create the zip artifact under
`target/release-audit/packages/`.
