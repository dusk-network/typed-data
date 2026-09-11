# Changelog

## [Unreleased]

### Added

- Extracted the existing typed-data protocol implementation from Connect for shared consumption by Wallet and Connect. ([wallet#22])
- Exposed tagged-message construction for wallet signers without adding a signing or key-management API. ([wallet#22])
- Added cross-implementation BLS vectors covering key derivation, the tagged
  signed message and signature bytes [wallet#22].

### Changed

- **Breaking:** `verifyTypedDataSignature` now requires a `{ chainId, origin }`
  policy and returns a structured result instead of a boolean [wallet#22].
- Pinned typed-data signatures to the V2 BLS scheme regardless of chain height [wallet#22].
- Applied the extra-key rule to every own property, matching the presence test [wallet#22].
- Scoped typed-data validation to reachable types and made error codes consistent
  across hashing entry points [wallet#22].
- Pinned `@noble/curves` and `@noble/hashes` to exact versions.

The package version `0.1.0-next.0` is an unpublished integration candidate, not a frozen protocol v1 release. Encoding and existing frozen vector bytes are unchanged.

[wallet#22]: https://github.com/dusk-network/wallet/issues/22
