# Changelog

## [Unreleased]

### Added

- Extracted the existing typed-data protocol implementation from Connect for shared consumption by Wallet and Connect. ([wallet#22])
- Exposed tagged-message construction for wallet signers without adding a signing or key-management API. ([wallet#22])

The package version `0.1.0-next.0` is an unpublished integration candidate, not a frozen protocol v1 release. Encoding and existing frozen vector bytes are unchanged.

[wallet#22]: https://github.com/dusk-network/wallet/issues/22
