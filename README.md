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

> Typed-data v1 is a draft and requires independent encoding review and an explicit
> specification declaration before freezing. Publishing a package does not freeze it.
> Pin the exact development version; do not assume draft v1 signatures remain
> compatible across releases. This release candidate is `0.1.0-rc.0`.

## Usage

This illustrative sign-in challenge demonstrates hashing with `@dusk/typed-data`,
not a complete login flow. For Wallet login/session authentication, prefer
[`dusk_signAuth`](https://github.com/dusk-network/wallet/blob/main/docs/provider-api.md#dusk_signauth),
which already supplies a login envelope:

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
Applications must still establish the expected schema, primary type, application
and contract, check the authorized signer, and enforce replay/expiry rules. Use
trusted request state, not a client's proposed schema or reported account identity.
The application example below demonstrates that boundary.

Wallets must supply the trusted requesting origin, enforce the active chain and
permissions, obtain approval, and recheck the signing context. Import
`checkPolicyLimits` from `@dusk/typed-data/policy` for the separate signer-side
resource check; it is not exported from the root and hashing does not apply it.
Verifiers must support otherwise-valid inputs within the spec's resource floor,
but may decline larger requests at their transport boundary. Invalid typed data
throws `TypedDataError` with an `E_*` code. The reference encoder also refuses
excessive structural work with `E_COMPLEXITY` on hash/debug/verification paths;
see [its documented above-floor guards](docs/typed-data-v1.md#111-reference-encoder-structural-guards).
This does not apply signer limits or change accepted digests. The initial
`validateTypedDataParams` shape check is not a full graph or resource check.

`buildTypedDataSignedMessage` constructs the tagged bytes a wallet signs.
`verifyBlsDigest` verifies a bare digest; it must not be used to verify typed-data
signatures. See the [specification](docs/typed-data-v1.md) for the format, supported
types and signing rules.

## Complete application-verification example

The [document-approval backend example](https://github.com/dusk-network/typed-data/blob/main/examples/approve-document.mjs)
uses the public verifier and Node's built-in SQLite. It adds no library exports,
wallet signing API, dependencies or generic authorization framework.

1. The server opens a durable database with `new DatabaseSync(path, { timeout: 5000 })`
   from `node:sqlite`, then calls `initApprovalStore(db)`.
2. After its own permission check, it calls
   `issueApproval(db, documentHash, authorizedPublicKeyHex)`. The document and key
   come from trusted application state, not an unauthenticated request. The stored
   grant fixes a random nonce and a five-minute expiry; deleting it revokes it.
3. A connected browser uses its selected Dusk Connect `provider` to request the
   expected Wallet account's signature on the configured chain, leaving origin
   injection to the Wallet:

   ```js
   const response = await provider.request({
     method: "dusk_signTypedData",
     params: {
       version: 1,
       domain: input.domain,
       types: input.types,
       primaryType: input.primaryType,
       message: input.message,
     },
   });
   // Submit { nonce: input.message.nonce, response } to the server.
   ```

4. The server calls `acceptApproval(db, nonce, response)`. It reconstructs the
   request from its stored grant and fixed schema/domain, verifies against the
   stored authorized key, checks `result.ok` and the configured origin/chain, then
   atomically records the approval. It does not trust response identity/digest
   echoes or accept a replacement input object from the client.

The conditional SQL update consumes the nonce **and records the document approval
in the same operation**, rechecking expiry and the exact grant. Two concurrent
submissions cannot both approve it. Uniqueness is per nonce, not per document; the
issuer decides whether to grant another approval. For a different business action,
put that action and nonce consumption in the same database transaction; do not copy this into a
check-then-act payment flow or assume it makes external side effects atomic.

This is an off-chain example: the omitted verifying contract deliberately means
32 zero bytes. Contract authorizations must instead establish their intended
contract and enforce its rules. Approving a document hash does not prove the user
saw the matching document; presenting that content remains the application's job.
Ordinary login should use `dusk_signAuth`, not this approval profile.

The example is backend logic, not a production HTTP service. Configure the actual
application domain/origin/chain, authenticate and authorize issuance, limit request
bodies/rates, use a trusted server clock and durable storage, and treat errors as
refusals. Its reply-size checks are local policy, not protocol limits. SQLite is a
single-host example; multiple hosts need shared transactional storage.

From a checkout, run `npm run build && npm run test:example`. The
[executable check](https://github.com/dusk-network/typed-data/blob/main/scripts/check-approval-example.mjs)
uses public test keys, real BLS verification and two SQLite worker connections,
including a forced concurrent replay. Never fund those test keys. This is not a
wallet/browser test or an independent encoder implementation.

## Development

Build and test from a checkout using Node 24 (the application example uses the
currently experimental `node:sqlite` API). The library itself remains usable in
its existing browser/Node/JSR environments; SQLite is not imported by its exports:

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
Native BLS checks do not independently validate the typed-data encoding. Before
freezing, obtain independent review of the accepted input space, encoding and
signing envelope, ideally with an independently written comparison of the existing
intermediate vectors. Before claiming a specific on-chain integration, also check
its actual contract/VM reconstruction and application policy. Neither the tests nor
package publication establish that certification.

## License

[MIT](LICENSE). Originally developed by [ichbindas](https://github.com/ichbindas) in
Dusk Connect. See [PROVENANCE.md](PROVENANCE.md) for authorship and import history.
