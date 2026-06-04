# CSE+

This repository is the public CSE+ envelope, verifier, and tooling line.

It contains the public wire, digest, and verification surface needed for tests
and reference integrations.

## Project Structure

- `crates/cse-plus-standard`: Public CSE+ metadata and helpers.
- `crates/tuff-cse-core`: Core digests, bundles, and profile helpers.
- `crates/tuff-cse-txn`: Wire packet v0, encode/decode, and verification API.
- `crates/tuff-cse-cli`: Command line interface.
- `crates/tuff-cse-adapter-http`: Reference HTTP adapter.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless explicitly stated otherwise, any contribution intentionally submitted for inclusion in this repository is dual-licensed as above, without additional terms or conditions.

## Disclosure Policy

The following components are intended for public verification and common implementation:
- Wire schema and encode/decode logic.
- Digest and seal interfaces.
- CLI verifier and KAT (Known Answer Tests).
- Reference adapters.
