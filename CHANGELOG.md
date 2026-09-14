# Changelog

## [Unreleased]

### Added

- Added a runnable application-approval example with atomic replay and expiry enforcement. ([wallet#22])
- Specified lossless approval disclosure before signing, independently of digest validity. ([#4])
- Exposed BLS V2 fixtures through the npm `./vectors/bls-signing/*` export. ([#2])
- Extracted the existing typed-data protocol implementation from Connect for shared consumption by Wallet and Connect. ([wallet#22])
- Exposed tagged-message construction for wallet signers without adding a signing or key-management API. ([wallet#22])
- Added cross-implementation BLS vectors covering key derivation, the tagged
  signed message and signature bytes [wallet#22].

### Changed

- Refuse excessive encoder structure with coded `E_COMPLEXITY` errors above the interoperability floor. ([#6])
- Require relying applications to enforce single-use and time-bounded authorization semantics. ([#7])
- Defined resource-floor measurements without changing the reference policy's acceptance behavior. ([#2])
- Clarified the compact-JSON size diagnostic while retaining `E_POLICY_LIMIT`. ([#2])
- Separated package publication from an explicit protocol-freeze declaration. ([wallet#22])
- Included input validity and signing rules in the protocol freeze's scope. ([wallet#22])
- **Breaking:** Moved `checkPolicyLimits` from the root export to `@dusk/typed-data/policy`. ([#2])
- Renamed the BLS corpus directory to `vectors/bls-signing/` without changing fixture bytes. ([#2])
- **Breaking:** `verifyTypedDataSignature` now requires a `{ chainId, origin }`
  policy and returns a structured result instead of a boolean [wallet#22].
- Pinned typed-data signatures to the V2 BLS scheme regardless of chain height [wallet#22].
- Applied the extra-key rule to every own property, matching the presence test [wallet#22].
- Scoped typed-data validation to reachable types and made error codes consistent
  across hashing entry points [wallet#22].
- Pinned `@noble/curves` and `@noble/hashes` to exact versions.

### Fixed

- Stream array/field encoding without JavaScript argument-spread limits. ([#6])
- Bound verification policy checks and returned context to the values used in the digest. ([wallet#22])
- Rejected undeclared symbol-keyed fields in typed-data structs. ([wallet#22])
- Rejected non-string origins returned by accessors during hashing. ([wallet#22])

The package version `0.1.0-next.0` is an unpublished integration candidate, not a frozen protocol v1 release. Encoding and existing frozen vector bytes are unchanged.

[#2]: https://github.com/dusk-network/typed-data/issues/2
[#4]: https://github.com/dusk-network/typed-data/issues/4
[#6]: https://github.com/dusk-network/typed-data/issues/6
[#7]: https://github.com/dusk-network/typed-data/issues/7
[wallet#22]: https://github.com/dusk-network/wallet/issues/22
