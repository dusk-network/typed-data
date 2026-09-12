# Dusk Typed Data

Dusk Typed Data is a JavaScript/TypeScript library for hashing structured messages
and verifying Dusk wallet signatures.

It is intended for off-chain requests such as signing in to a dApp or approving an
application action. Each request describes the fields being signed and binds the
message to an application, chain and requesting origin. A wallet can use those
fields to show the request before signing.

The library provides the encoding and verification code. It does not manage keys,
provide an approval UI or submit transactions. For wallet discovery and requests,
see [Dusk Connect](https://github.com/dusk-network/connect).

> Typed-data v1 is a draft and requires independent encoding review before freezing.
> The package has not been published to npm or JSR.

## Usage

Hash a sign-in challenge using the `@dusk/typed-data` entrypoint:

```ts
import { hashTypedDataHex } from "@dusk/typed-data";

const input = {
  domain: { name: "Example", version: "1", chainId: "dusk:2" },
  types: {
    DuskTypedDataDomain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "string" },
      { name: "verifyingContract", type: "bytes32" },
    ],
    SignIn: [
      { name: "statement", type: "string" },
      { name: "nonce", type: "string" },
    ],
  },
  primaryType: "SignIn",
  message: {
    statement: "Sign in to Example",
    nonce: "server-issued-one-time-challenge",
  },
  origin: "https://app.example",
};

const digestHex = hashTypedDataHex(input);
```

With the wallet's signing result in `response`, verify the signature using its
reported origin and your application's expected chain and origin:

```ts
import { verifyTypedDataSignature } from "@dusk/typed-data/bls";

const result = verifyTypedDataSignature(
  { ...input, origin: response.origin },
  response.signature,
  response.publicKeyHex,
  { chainId: "dusk:2", origin: "https://app.example" },
);

if (!result.ok) throw new Error(result.code);
```

Check `result.ok`, not the result object itself. Both policy fields are required;
`null` explicitly skips a check. Verification uses Dusk's BLS V2 scheme.
Applications must still check the expected signer and enforce authorization and
replay protection, such as consuming the nonce and checking expiry.

Wallets must supply the trusted requesting origin, enforce the active chain and
permissions, obtain approval, and recheck the signing context. Import
`checkPolicyLimits` from `@dusk/typed-data/policy` for the separate signer-side
resource check; it is not exported from the root and hashing does not apply it.
Verifiers must support otherwise-valid inputs within the spec's resource floor,
but may decline larger requests at their transport boundary. Invalid typed data
throws `TypedDataError` with an `E_*` code.

`buildTypedDataSignedMessage` constructs the tagged bytes a wallet signs.
`verifyBlsDigest` verifies a bare digest; it must not be used to verify typed-data
signatures. See the [specification](docs/typed-data-v1.md) for the format, supported
types and signing rules.

## Development

Build and test from a checkout:

```sh
npm ci
npm run ci
```

The build produces ESM JavaScript and TypeScript declarations in `dist/`. To create
a package for local use, run `npm pack`.

To regenerate the test vectors and compare BLS results with the Rust implementation:

```sh
npm run generate:typed-data-vectors
npm run generate:bls-vectors
npm run test:bls-native # Requires Rust and Cargo.
```

Node consumers can resolve the typed-data fixtures via `@dusk/typed-data/vectors/*`
and the BLS V2 signing fixtures via `@dusk/typed-data/vectors/bls-signing/*`.
The latter live in `vectors/bls-signing/`; the directory name is not a signing-scheme version.

The vectors contain public test seeds and keys. Never use them for funded accounts.
Native BLS checks do not independently validate the typed-data encoding.

## License

[MIT](LICENSE). Originally developed by [ichbindas](https://github.com/ichbindas) in
Dusk Connect. See [PROVENANCE.md](PROVENANCE.md) for authorship and import history.
