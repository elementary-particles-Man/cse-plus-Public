# Three-Bank Quick Harness

This quick harness prepares three local demo banks and runs a short verification
loop across the following branch IDs:

- `A001-001`
- `B002-001`
- `C003-001`

Payload sizes are mixed across 1 KiB, 10 KiB, 50 KiB, and 1 MiB cases. The
default quick mode uses 10 iterations per class per pair.

Normal and abnormal cases run actual packet verification. Cross-bank mismatch
rows are marked as public quick harness simulation because the public standard
line does not model full bank-profile binding.

Generated files:
- `target/release-audit/three-bank-local/topology.json`
- `target/release-audit/test-results/three-bank-quick-results.jsonl`
- `target/release-audit/test-results/three-bank-quick-summary.json`
