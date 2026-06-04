# Result Log Schema

The three-bank quick harness writes JSONL rows to
`target/release-audit/test-results/three-bank-quick-results.jsonl`.

Each row contains:
- `case_id`
- `case_class`
- `harness_mode`
- `source`
- `destination`
- `payload_size`
- `payload_digest`
- `expected_result`
- `actual_result`
- `activation_allowed`
- `rejection_reason`
- `elapsed_ms`

The summary JSON contains total counts, pass/fail counts, and breakdowns by case
class, harness mode, bank pair, and payload size.
