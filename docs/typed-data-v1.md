# Dusk Typed Data v1 — normative specification

**Status:** Draft. Not frozen.
**Scheme identifier:** `DUSK_TYPED_DATA_V1`
**Supersedes:** all earlier `v1` drafts and golden vectors. See [Changes from the pre-freeze draft](#changes-from-the-pre-freeze-draft).

This document is the single source of truth for the Dusk typed-data digest. Every
implementation — the shared reference (`@dusk/typed-data`) used by Connect and
Wallet, and any contract-side or relayer verifier — MUST
produce byte-identical digests and MUST agree on which inputs are valid.

Where this document says MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, the terms carry
their RFC 2119 meanings.

---

## 1. Scope

Dusk typed data lets a dApp ask a wallet to sign **structured, human-renderable
data** instead of an opaque digest. It is the Dusk analogue of EIP-712 /
`eth_signTypedData_v4`, not of `eth_sign`.

It is deliberately **not** wire-compatible with EIP-712: different hash function
(SHA-256, not keccak-256), different curve and signature scheme (BLS12-381 short
signatures, not secp256k1 ECDSA), different type encoding. Familiarity is the
only thing borrowed.

### 1.1 Goals

- A verifier that holds the payload can recompute the digest independently.
- The requesting web origin is bound into the digest by the **wallet**, not the caller.
- The encoded form is a function of the **type**, not the **value**, so no
  implementation needs a size budget to agree with any other.
- The tagged signed message is disjoint from bare 32-byte messages signed by the
  same key under the same DST (§12.1).

### 1.2 Non-goals

- Ethereum tooling compatibility.
- Replacing transaction approval. A typed-data signature never moves funds by itself.
- Decoding arbitrary contract calldata.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| **atomic type** | One of `string`, `bytes`, `bytes32`, `uint64`, `uint32`, `uint8`, `bool` |
| **struct type** | A named entry in `types` whose value is a list of field definitions |
| **array type** | `T[n]` for a fixed `n ≥ 1`, where `T` is any non-array type |
| **field definition** | `{ "name": <identifier>, "type": <type expression> }` |
| **identifier** | A string matching `^[A-Za-z_][A-Za-z0-9_]*$` |
| **signer** | An implementation that produces signatures (the wallet) |
| **verifier** | An implementation that checks signatures (Connect, a relayer, a contract) |

All byte strings are big-endian unless stated. `sha256(x)` denotes SHA-256 over
byte string `x`, producing exactly 32 bytes. `utf8(s)` denotes the UTF-8 encoding
of Unicode string `s`. `a || b` denotes concatenation.

---

## 3. Input

```jsonc
{
  "domain": {
    "name":    "<string>",
    "version": "<string>",
    "chainId": "<string>",           // CAIP-2, e.g. "dusk:1"
    "verifyingContract": "<0x-hex>"  // OPTIONAL, exactly 32 bytes when present
  },
  "types": {
    "DuskTypedDataDomain": [ /* canonical, see §7 */ ],
    "<StructName>": [ { "name": "...", "type": "..." }, ... ]
  },
  "primaryType": "<StructName>",
  "message":     { /* value of primaryType */ },
  "origin":      "<string>"          // injected by the signer, see §8
}
```

`origin` is **not** a caller-supplied field at the RPC boundary. The signer
overwrites any caller-supplied value. See §8.

---

## 4. Type expressions

A type expression is exactly one of:

1. An atomic type name.
2. A struct type name — an identifier that is a key of `types`.
3. `T[n]` where `T` is an atomic or struct type name and `n` matches `^[1-9][0-9]*$`.

Nested arrays (`T[n][m]`) are permitted; the inner expression is parsed first.

Implementations MUST reject:

- Any type expression containing whitespace.
- Dynamic arrays (`T[]`), including any expression containing `[]`.
- Zero-length arrays (`T[0]`) and arrays with leading zeros in `n` (`T[01]`).
- A struct type name that is not a key of `types`.
- A struct type name that is not a valid identifier.

### 4.1 Encoded width

Every type has a width determined statically from the type expression alone:

| Type | Width (bytes) |
|------|---------------|
| `bool` | 1 |
| `uint8` | 1 |
| `uint32` | 4 |
| `uint64` | 8 |
| `bytes32` | 32 |
| `string` | 32 |
| `bytes` | 32 |
| struct | 32 |
| `T[n]` | `n × width(T)` |

This is the central property of v1: **encoded size never depends on the value.**
Implementations therefore do not need, and MUST NOT apply, a value-dependent size
budget as a validity rule. See §11.

---

## 5. Value encoding

`encodeValue(T, v)` produces exactly `width(T)` bytes.

### 5.1 Atomics

| Type | Accepted JSON | Encoding |
|------|---------------|----------|
| `bool` | boolean only | `0x01` if true, `0x00` if false |
| `uint8` | see §5.2 | 1-byte big-endian |
| `uint32` | see §5.2 | 4-byte big-endian |
| `uint64` | see §5.2 | 8-byte big-endian |
| `bytes32` | hex string decoding to **exactly** 32 bytes, `0x` prefix optional | the 32 raw bytes |
| `string` | string only | `sha256(utf8(v))` |
| `bytes` | hex string, any length including empty, `0x` prefix optional | `sha256(rawBytes)` |

Hex decoding: an optional `0x` or `0X` prefix MAY be present; the remainder MUST
have even length and contain only `[0-9a-fA-F]`. `bytes32` MUST NOT be
zero-padded or truncated — a value that does not decode to exactly 32 bytes is
rejected, not adjusted.

Strings are hashed over their UTF-8 bytes with **no normalization**. Implementations
MUST NOT apply NFC, NFD, case folding, or whitespace trimming. Two strings that
differ by a combining-character sequence are different values.

Every string passed to `utf8`, including domain fields and origin, MUST contain
only Unicode scalar values. An unpaired UTF-16 surrogate, including one introduced
by a JSON escape, MUST be rejected with `E_UTF8`, never replaced with U+FFFD.
Valid surrogate pairs and a literal U+FFFD remain valid.

`sha256("")` is a well-defined constant, so an empty `string` and an empty `bytes`
both encode to `e3b0c442...b855`. This is not a collision: field types are pinned
by `typeHash` (§6.2), which is the first 32 bytes of every struct preimage.

### 5.2 Unsigned integers

A `uintN` value MUST be either:

- a JSON **number** that is an integer and satisfies `Number.isSafeInteger`
  (i.e. `|v| ≤ 2^53 − 1`), or
- a JSON **string** matching `^(0|[1-9][0-9]*)$` (decimal, no sign, no leading zeros).

The value MUST be `≥ 0` and `≤ 2^N − 1`.

Callers SHOULD use the decimal-string form for any `uint64` value, and MUST use it
above `2^53 − 1`. The JSON-number path is accepted for ergonomics only; it cannot
represent the full `uint64` range and MUST NOT be silently widened.

### 5.3 Arrays

`encodeValue(T[n], v)`: `v` MUST be a JSON array of exactly `n` elements. The
encoding is the concatenation of `encodeValue(T, v[i])` for `i` in `0..n-1`.

### 5.4 Structs

`encodeValue(S, v)` where `S` is a struct type is `structHash(S, v)` — see §6.3.
`v` MUST be a JSON object (not `null`, not an array).

---

## 6. Type and struct hashing

### 6.1 encodeType

`encodeTypeLocal(S)` is the string:

```
S(t1 n1,t2 n2,...,tk nk)
```

where `ti`/`ni` are the declared type and name of the `i`-th field of `S`, in
declaration order, joined by `,` with no spaces except the single space between
each type and name. Field names MUST match the identifier grammar in §2;
non-identifiers MUST be rejected before encoding, so names cannot inject delimiters.

`deps(S)` is the set of struct type names reachable from `S` by following field
types, unwrapping array types, transitively, **including `S` itself**.

`encodeType(S)` is:

```
encodeTypeLocal(S)  ||  concat( encodeTypeLocal(D) for D in sorted(deps(S) \ {S}) )
```

The primary type comes **first**; remaining dependencies follow, sorted ascending
by type name comparing UTF-8 bytes.

> **Note.** Sorting by type name and sorting by the full `encodeTypeLocal` string
> are equivalent here, because `(` is `0x28`, which is below every byte legal in an
> identifier (`0`=0x30, `A`=0x41, `_`=0x5F, `a`=0x61), and type names are unique
> within `types`. Implementations MAY sort by either key. This spec states the
> name-sorted form because it matches EIP-712's wording.

### 6.2 typeHash

```
typeHash(S) = sha256( utf8( encodeType(S) ) )
```

### 6.3 structHash

```
structHash(S, v) = sha256( typeHash(S) || encodeValue(t1, v[n1]) || ... || encodeValue(tk, v[nk]) )
```

fields in declaration order.

Field presence MUST be tested as an **own** property of `v` — never via prototype
chain lookup (`in` in JavaScript, `hasattr` on a class instance, etc.). Every field
declared by `S` MUST be present; any key of `v` not declared by `S` MUST be rejected.

Both rules use the same notion of **own**: every own property, whether or not it
is enumerable. This includes JavaScript symbol keys, which cannot be declared by
the identifier grammar and MUST be rejected with `E_FIELD_EXTRA`.
An implementation that tests presence over all own properties but
collects extra keys from the enumerable ones only would treat a non-enumerable
own property as present while never rejecting it as undeclared. Values that
arrive by parsing JSON have only enumerable own properties, so the distinction
is unreachable across a transport boundary and reachable only for a caller
constructing the object in process.

---

## 7. Domain

`types` MUST contain a `DuskTypedDataDomain` entry equal to exactly:

```json
[
  { "name": "name",              "type": "string" },
  { "name": "version",           "type": "string" },
  { "name": "chainId",           "type": "string" },
  { "name": "verifyingContract", "type": "bytes32" }
]
```

Same fields, same types, same order, no additions. Any deviation is rejected.

The canonical domain value is:

```
{
  name:              domain.name,
  version:           domain.version,
  chainId:           domain.chainId,
  verifyingContract: domain.verifyingContract ?? "0x0000...0000"   // 32 zero bytes
}
```

`name`, `version`, and `chainId` MUST be strings. `verifyingContract`, when
present, MUST be a string; it is encoded as `bytes32` per §5.1, so it MUST decode
to exactly 32 bytes. Omitting it is exactly equivalent to supplying 32 zero bytes.

```
domainSeparator = structHash("DuskTypedDataDomain", canonicalDomain)
```

`primaryType` MUST NOT be `DuskTypedDataDomain`.

---

## 8. Origin binding

```
ORIGIN_TAG = utf8("DUSK_ORIGIN_BIND_V1\0")        // 20 bytes
originBind = sha256( ORIGIN_TAG || sha256(utf8(origin)) )
```

`origin` MUST be a string. It is supplied by the **signer**, from its own trusted
view of the requesting context — for a browser extension, the origin of the page
that issued the RPC.

A signer MUST ignore and overwrite any `origin` field present in caller-supplied
parameters. A caller that could set `origin` could obtain a signature attributable
to a site it does not control.

Signers MUST NOT normalize the origin (no trailing-slash addition or removal, no
case folding, no default-port stripping) beyond what the host platform already
guarantees. The exact string used MUST be returned to the caller (§13) so that a
verifier reconstructs it rather than guessing.

Non-browser signers MAY use the empty string when no web origin exists. The empty
string is a distinct, well-defined binding — it is not a wildcard, and a verifier
MUST NOT treat it as matching any origin.

---

## 9. Digest

```
PREAMBLE = utf8("DUSK_TYPED_DATA_V1\0")           // 19 bytes

digest = sha256(
    PREAMBLE                                       // 19 bytes
 || domainSeparator                                // 32 bytes
 || originBind                                     // 32 bytes
 || structHash(primaryType, message)               // 32 bytes
)                                                  // = 115-byte preimage
```

The preimage is fixed-length, so the four components are unambiguously positioned
and no length prefixes are required.

---

## 10. Validation

The following are **normative rejects**. Implementations MUST reject all of them,
MUST NOT coerce or repair, and SHOULD report the stable error code so that two
implementations disagreeing can be diagnosed.

| Code | Condition |
|------|-----------|
| `E_PARAMS_SHAPE` | Input is not an object; `types`, `domain`, or `message` is not a non-array object |
| `E_PRIMARY_MISSING` | `primaryType` absent, not a string, or not a key of `types` |
| `E_PRIMARY_INVALID` | `primaryType` is an atomic, an array type, not an identifier, or is `DuskTypedDataDomain` |
| `E_DOMAIN_TYPE` | `types.DuskTypedDataDomain` absent or not exactly the canonical field list (§7) |
| `E_DOMAIN_VALUE` | `domain.name`/`version`/`chainId` not strings, or `verifyingContract` present and not a string |
| `E_TYPE_UNKNOWN` | A referenced struct type is not a key of `types` |
| `E_TYPE_INVALID` | Type expression contains whitespace, is `T[]`, is `T[0]`, has leading zeros in `n`, or names a non-identifier |
| `E_TYPE_CYCLE` | The struct dependency graph reachable from `primaryType` or `DuskTypedDataDomain` contains a cycle |
| `E_FIELD_DUP` | Two fields of one struct share a name |
| `E_FIELD_RESERVED` | A field is named `__proto__`, `constructor`, or `prototype` |
| `E_FIELD_DEF` | A field definition's `name` is not an identifier or its `type` is not a string |
| `E_FIELD_MISSING` | A declared field is not an own property of the value |
| `E_FIELD_EXTRA` | The value has an own property not declared by its struct type |
| `E_VALUE_TYPE` | Value's JSON type does not match the declared type (§5.1) |
| `E_ARRAY_LENGTH` | Array value's length ≠ the declared `n` |
| `E_UINT_RANGE` | Integer negative, above `2^N − 1`, or a JSON number that is not a safe integer |
| `E_UINT_FORMAT` | Integer string does not match `^(0\|[1-9][0-9]*)$` |
| `E_HEX_FORMAT` | Hex string has odd length or non-hex characters |
| `E_BYTES32_LENGTH` | `bytes32` value does not decode to exactly 32 bytes |
| `E_ORIGIN_TYPE` | `origin` is not a string |
| `E_UTF8` | A string passed to `utf8` contains an unpaired UTF-16 surrogate |

Type cycles (`E_TYPE_CYCLE`) admit no finite value, so they were previously
unreachable in practice. They are rejected explicitly so that validity does not
rest on an unstated invariant, and so the error is reported at the type level
rather than as a confusing `E_FIELD_MISSING` deep in recursion.

Reserved field names (`E_FIELD_RESERVED`) are rejected because prototype-chain
lookup for those names succeeds on an empty object in several languages,
which would let a declared field appear present when it is absent.

### 10.1 Validation scope

Validation applies to the types the message actually uses: the struct types
reached from `primaryType` and from `DuskTypedDataDomain` by following field
types, together with their transitive dependencies.

An entry of `types` that is not reachable that way is not validated, and MUST
NOT cause a reject. Such an entry cannot affect the digest. `encodeType` (§6.1)
emits the primary type and its transitive dependencies only, so an unreferenced
type contributes to no type hash, to no struct hash, and to no field a signer
displays for approval.

This lets a caller send one `types` dictionary covering several different
messages and select among them with `primaryType`, without every unused entry
having to satisfy every rule.

Implementations MUST NOT reject an input because an unreachable entry is
malformed, and MUST NOT accept an input because a malformed reachable type
also appears, well-formed, under another name.

### 10.2 Reporting the code

An input may break several rules at once. Such an input MUST be rejected, but
this specification does not fix which code is reported for it: two
implementations MAY report different codes for the same multi-violation input,
and both are conformant. Test vectors therefore pin an error code only for an
input that breaks exactly one rule.

Within one implementation the reported code MUST be stable. An implementation
that exposes more than one validating entry point — for example one returning
the digest alone and one also returning the intermediates of §9 — MUST report
the same code from each for the same input. Otherwise a consumer diagnosing a
disagreement between two implementations gets a different answer depending on
which function it happened to call.

An implementation SHOULD document the order in which it checks. The reference
implementation validates the input shape first, then computes the digest stages
of §9 in order, so defects in the domain are reported before defects in the
message, and defects in a type expression are reported when that type is first
used.

---

## 11. Limits

Encoded size is a function of the type (§4.1), so **no size limit is part of digest
validity**. This is a deliberate change from the pre-freeze draft, where a 1 MiB
encoded-size budget was normative and the two reference implementations diverged
on how to count it.

Instead, this spec defines a **floor**, not a ceiling:

| Dimension | Floor |
|-----------|-------|
| Distinct reachable struct types | 32 |
| Fields per reachable struct | 64 |
| Value traversal depth | 8 |
| Elements per fixed array | 256 |
| Decoded bytes per typed `string` or `bytes` value | 65 536 |
| Compact JSON input, in UTF-8 bytes | 262 144 |

The first five measurements traverse the domain and primary message using their
reachable schema (§10.1), counting `DuskTypedDataDomain` once. Each root struct
starts at depth 1; entering a field value or array element adds 1, **including
atomic leaves**. String values count their UTF-8 bytes without normalization;
`bytes` values count their decoded bytes, not their hexadecimal spelling.

The total is the UTF-8 byte length of the complete JSON input of §3 after compact
serialization, including the signer-injected origin, schema, JSON syntax and any
unused metadata. The reference measurement is
`new TextEncoder().encode(JSON.stringify(input)).length`, with no replacer or
indentation. Other implementations MUST use an equivalent byte count for this
floor: use [ECMAScript JSON serialization](https://tc39.es/ecma262/#sec-json.stringify)
for strings and numbers, not ASCII-only escaping or pretty-printing. Object member
order does not affect the count.
Hexadecimal fields count as text here: two 65,536-byte values alone require 262,144
hexadecimal characters, before prefixes, schema and JSON syntax.

This clarifies the earlier label "total decoded input"; it is **not** a sum of
decoded typed-value bytes, the raw incoming wire size, a disclosure-text size, or a
peak-memory guarantee. Different accepted representations, such as `42` versus
`"42"` for a `uint64` or prefixed versus prefixless hex, can encode the same typed
value but have different policy costs. Raw transport limits and signer disclosure
limits are additional local policy; none changes hashing or input validity.

Rules:

- **Verifiers MUST accept** any otherwise-valid payload within the floor.
- **Signers SHOULD reject** payloads exceeding the floor, as local policy, with an
  error distinguishable from the §10 validation codes (suggested: `E_POLICY_LIMIT`).
- Implementations MAY accept payloads above the floor, but a signer that does so
  risks producing signatures a conforming verifier is not obliged to check. Signers
  SHOULD NOT.
- Limits MUST NOT influence the digest. Two implementations that both accept a
  payload MUST produce the same digest regardless of their limits.

This confines resource policy to the transport boundary, where implementations may
differ safely, and keeps it out of the consensus rules, where they may not.

---

## 12. Signing and verification

### 12.1 Signed message

The signature is **not** computed over the bare digest. It is computed over:

```
SIG_TAG        = utf8("DUSK_TYPED_DATA_SIG_V1\0")      // 23 bytes
signedMessage  = SIG_TAG || digest                     // 55 bytes
```

Rationale: the digest is 32 bytes and therefore indistinguishable from any other
32-byte value the same key might be asked to sign — including Moonlight pay-auth
digests. The tag makes the typed-data message space structurally disjoint from
every 32-byte message space, so an implementation that signs raw 32-byte digests
cannot forge a typed-data signature, and vice versa.

The tag is applied outside the digest because a value inside the SHA-256 preimage
does not constrain the *output*, which is what actually gets signed.

This is not separation from an unrestricted arbitrary-byte signing API using the
same key and DST: that API could sign this exact 55-byte message without the
typed-data approval/context checks. Any additional signing API needs its own
cross-protocol message-space review; the tag does not protect against such an
arbitrary-message signing oracle.

### 12.2 Algorithm

Before obtaining approval and producing a signature, a signer MUST meet the
[approval-disclosure requirements in §16](#16-approval-disclosure).

```
sk        = profile Moonlight BLS12-381 secret key
DST       = "BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_V2"
signature = sk · hashToCurve_G1(signedMessage, DST)      // 48-byte compressed G1
publicKey = 96-byte compressed G2 point
```

The DST is the standard Dusk `BlsVersion::V2` domain separation tag, unchanged,
and is fixed for all typed-data signatures regardless of chain state (§12.4).
This keeps signatures verifiable by the stock dusk-core verification path, which
does not accept a caller-supplied DST. `hashToCurve` accepts arbitrary-length
input, so the 55-byte tagged message needs no special handling.

### 12.3 Verification

A verifier MUST:

1. Recompute `digest` from the payload — including the `origin` the signer reports,
   not one the verifier assumes.
2. Recompute `signedMessage = SIG_TAG || digest`.
3. Verify the short signature over `signedMessage` under the standard DST.
4. Check `domain.chainId` against the chain it is verifying for.
5. Check `origin` against its own policy. An origin that does not match expectation
   MUST fail verification even when the signature is cryptographically valid.

A verifier MUST NOT verify over the bare digest. Doing so would accept signatures
produced by any raw-32-byte signing path.

These steps do not authorize an application action. The application must establish
its expected schema/primary type, domain name/version and verifying contract, the
authorized signer, and any nonce/expiry rules. Constructing the input from trusted
server state is one way to establish those expectations; accepting an arbitrary
client-supplied schema and a valid signature is not. A reported account name or
public key is not proof that the key is authorized. One-time actions require an
atomic replay check and state transition, not a separate check-then-mark sequence.

Origin binding records the signing context; it is not browser-origin attestation
or proof of adequate disclosure. Applications with multiple frontends or migrating
origins must deliberately define their acceptance policy. Changing an expected
origin, or copying it from an untrusted response, is not a substitute for that
policy. Nonces and expiry remain separate from origin/chain binding.

### 12.4 Signature scheme version

Typed-data signatures are **V2-only, unconditionally**.

A signer MUST sign under `BlsVersion::V2`. A verifier MUST verify under
`BlsVersion::V2`. Neither MUST dispatch on block height, fork state, or any
chain-provided version signal, and an implementation MUST NOT expose V1 for
typed data even when the BLS library it uses offers it.

This is a deliberate departure from how the chain itself treats the BLS version.
On chain the scheme is height-dependent — `bls_version_at(block_height)` resolves
to V1 before the Aegis activation height and V2 from Aegis onwards — because
blocks and transactions signed before the fork must stay verifiable. Typed data
has no such history: the scheme was introduced after Aegis, so no typed-data
signature predates V2 and there is nothing to remain compatible with.

Rationale for pinning rather than inheriting:

- V1 is the insecure path (`verify_insecure` / `sign_insecure`), which does not
  use RFC 9380 hash-to-curve. A height-dependent typed-data path would add a
  downgrade surface to a scheme that never needs one.
- A verifier is not necessarily a node. A dApp checking a signature has no
  reliable notion of "the block height this was signed at", so a
  height-dependent rule would be unimplementable off-chain without inventing one.
- Digests are computed and approved by a user at a point in time, but may be
  verified arbitrarily later. A rule that varied with chain state would make the
  validity of an already-approved signature time-dependent.

Accept vectors carry `params.blsVersion` so this is asserted rather than assumed
(§15).

If Dusk introduces a future BLS version, typed-data v1 stays on V2. Adopting a
new signature scheme version is a change to §12 and therefore requires a new
scheme identifier under the freeze rule (§14).

---

## 13. Result shape

A signer returns:

```jsonc
{
  "account":       "<base58 Moonlight account>",
  "publicKeyHex":  "0x<96-byte compressed G2>",
  "origin":        "<exact origin string used in the digest>",
  "chainId":       "<CAIP-2 chain the signer was on>",
  "primaryType":   "<primaryType that was signed>",
  "digestHex":     "0x<32-byte bare digest>",
  "signature":     "0x<48-byte compressed G1>"
}
```

`origin` MUST be echoed. It is a digest input the caller does not control, and a
verifier that guesses it wrong cannot distinguish a normalization mismatch from a
tampered signature.

`digestHex` is the **bare** digest (§9), suitable for display and for a caller to
cross-check. The signature covers `SIG_TAG || digest` (§12.1), not this value.

`account` and `publicKeyHex` are two encodings of the same key: `account` is the
base58 form used throughout the rest of the provider surface, `publicKeyHex` is the
raw form a verifier passes to the BLS library.

---

## 14. Versioning

- A wallet advertises `signTypedDataVersions: [1]` — an **array**, so that a future
  version can be added without breaking callers that speak only v1, and so that
  retiring a version is detectable by callers rather than surfacing as an opaque
  runtime rejection.
- A caller MAY send `params.version`. It defaults to `1`. A signer MUST reject a
  version it does not implement rather than falling back silently, so that a caller
  which precomputed a digest locally gets a clear error instead of a mismatch.
- **Freeze rule.** Publishing a package or wallet build does not by itself freeze
  `DUSK_TYPED_DATA_V1`. The scheme remains draft until independent encoding review
  is completed and this specification explicitly declares v1 frozen. Before that
  declaration, vectors may be regenerated; this document does not declare a freeze.
- **Frozen scope.** Once frozen, changes to the specified accepted typed-data values
  or their encoding/hashing (§4–§10), or to the signed message or signature algorithm (§12,
  including `SIG_TAG`, the BLS version and DST), require a new scheme identifier.
  Editorial clarifications that preserve behavior, application policy and display
  changes within §11/§16 do not by themselves require a new identifier.
- **Draft compatibility.** Experimental integrations SHOULD pin their exact package
  version and retain the corresponding source/vector revision. The draft label
  `DUSK_TYPED_DATA_V1` alone does not identify a stable encoding across development
  releases. Long-lived or production authorizations SHOULD wait for an explicit
  freeze; package version `0.1.0` would not by itself establish one.

---

## 15. Test vectors

Golden vectors are the interoperability contract. They live in one place and are
mirrored, never re-derived. Every vector MUST carry intermediates, not only the
final digest — a mismatch must localize to a stage.

Each **accept** vector:

```jsonc
{
  "description": "...",
  "input":       { "domain": …, "types": …, "primaryType": …, "message": …, "origin": … },
  "typeHashes":  { "<StructName>": "0x…" },
  "domainSeparator": "0x…",
  "originBind":      "0x…",
  "structHash":      "0x…",
  "digestHex":       "0x…",
  "signedMessageHex":"0x…"
}
```

Each **reject** vector: `{ "description", "input", "error": "E_…" }`.

Required accept coverage: minimal string struct; nested struct; `bytes32` field
with non-zero `verifyingContract`; domain without `verifyingContract`; fixed array;
nested fixed array; empty `string`; empty `bytes`; `uint64` at `2^64 − 1` as
decimal string; `uint64` as JSON number; multi-byte and combining-character UTF-8
string; struct reached through an array element.

Required reject coverage: one vector per §10 error code.

---

## 16. Approval disclosure

These requirements govern a signer's approval interface, not digest validity or
verification. A valid signature does not establish that its signer met them.

1. **Disclose before signing.** A signer MUST NOT enable approval or sign a
   payload it cannot fully disclose. The disclosure MUST correspond to the same
   validated input used for the digest and signature, including the signer's own
   origin. Sanitizing, escaping, clipping or normalizing display text MUST NOT
   change the input that is signed.
2. **Complete access.** Every value that enters the digest MUST be reachable by
   the user, directly or through an explicit expand, scroll or pagination
   affordance. This includes complete strings and bytes, all array elements and
   nested values, the domain (including implicit defaults), `primaryType` and
   the reachable declared schema in declaration order. A bounded preview MAY
   summarize these, but an omitted-value count, ellipsis, warning, byte hash or
   digest alone MUST NOT substitute for access to the complete values.
3. **Unambiguous structure and types.** Fields MUST retain unambiguous boundaries,
   paths and their declared schema types, never types inferred from values.
   A struct with no fields MUST still be disclosed by path and type, including
   an empty root or array element. A structured full view MAY convey paths
   through its object/array structure and types through the accompanying schema.
   Unused types (§10.1) and extra metadata MUST NOT be described as contributing
   to the digest.
4. **Trusted origin.** The disclosed origin MUST be the exact one injected by
   the signer under §8, not a caller-supplied `origin` parameter.
5. **Safe text boundaries.** Every Unicode `Bidi_Control` character MUST be
   neutralized in the display. Here, "invisible formatting controls" means
   `General_Category=Format` (`Cf`) in the
   [Unicode Character Database](https://www.unicode.org/reports/tr44/).
   These MUST be visibly escaped or substituted and flagged, including U+200B,
   U+200C, U+200D, U+2060, U+FEFF and U+00AD. Values containing LF, CR, U+2028 or
   U+2029 MUST be flagged and escaped or isolated so they cannot fabricate
   another field. Line-joined preview text MUST NOT be treated as a canonical
   serialization.

   Both properties use the Unicode database supplied by the signer's runtime or
   Unicode library; the display repertoire follows upgrades to that database.
   These are display requirements, not input-rejection or normalization rules,
   and such upgrades MUST NOT affect hashing or input validity. There are no
   shaping or emoji exceptions to this display handling.
   `Default_Ignorable_Code_Point` is a different repertoire: code points outside
   `Cf`, such as U+034F COMBINING GRAPHEME JOINER, still require lossless access
   under rule 6.
6. **Lossless originals.** Original strings MUST remain accessible in an
   unambiguous escaped or code-point form, including characters replaced in a
   readable preview. Literal escape spellings MUST remain distinguishable from
   escaped characters. Comparisons of signing requests MUST NOT treat NFC/NFD
   equivalents as identical: `"\u00e9"` and `"e\u0301"` sign differently under
   §5.1. A signer SHOULD flag non-NFC sequences, not silently normalize them
   away. ZWJ/ZWNJ and other shaping controls can have legitimate uses; a warning
   is not a determination of malicious intent.
7. **Fail closed on display limits.** A signer MAY impose local disclosure
   resource limits. If complete disclosure cannot be provided, it MUST refuse
   signing with a clear explanation rather than sign hidden content. This does
   not change the verifier resource floor in §11 or any encoding rule.

A bounded field preview with a full escaped JSON inspector is one possible
implementation, not a required UI or another wire encoding. Rendering belongs
to the signer; hashing and verification libraries need not provide a renderer.

Ordinary JSON serialization (for example, `JSON.stringify(payload, null, 2)`)
does not by itself provide this escaped view: it leaves many non-ASCII
characters unescaped. The view must make the original character sequence
unambiguous, including non-ASCII characters, formatting controls and literal
escape introducers. For example, each pair below denotes distinct originals:

```text
"\u00e9"        versus "e\u0301"
"Ali\u200bce"   versus "Ali\\u200bce"
```

---

## Changes from the pre-freeze draft

| Change | Reason |
|--------|--------|
| `string` and `bytes` encode as `sha256(value)` instead of `len32(value) \|\| value` | Makes encoded width a function of the type, removing the need for a normative size budget — the two reference implementations had diverged on how to count it, so each accepted payloads the other rejected |
| Normative 1 MiB encoded-size cap removed; §11 floor added | Resource policy belongs at the transport boundary, not in validity rules |
| `encodeType` prepends the primary type before sorted dependencies | Previously, two struct types with equal dependency-closure *sets* shared a `typeHash`. Only reachable for mutually recursive types, which admit no finite value — but the safety argument was implicit and unenforced |
| Type cycles rejected explicitly (`E_TYPE_CYCLE`) | Removes reliance on the above invariant; better error locality |
| Field presence via own-property lookup only | `in` succeeds via the prototype chain for `__proto__`, `constructor`, `toString`, so a declared field could appear present while absent |
| `__proto__`, `constructor`, `prototype` rejected as field names | Defence in depth for the same class of issue across languages |
| `primaryType` may not be `DuskTypedDataDomain` | No use case; produced a confusing approval screen |
| `originBind` hashes the origin instead of length-prefixing it | Consistency with §5.1 — one rule for variable-length input |
| Signature covers `SIG_TAG \|\| digest` rather than the bare digest | Makes the typed-data message space disjoint from 32-byte digest spaces signed by the same key under the same DST |
| Signing DST unchanged | A custom DST would break verification via the stock dusk-core path, which does not accept a caller-supplied DST |
| Result echoes `origin`, `chainId`, `primaryType`; `fundsPkHex` renamed `publicKeyHex`; `signatureHex` renamed `signature` | `origin` is a digest input the caller cannot derive reliably; the other names align with `dusk_signMessage` and `dusk_signAuth` |
| Capability is `signTypedDataVersions: [1]` | A scalar forces a flag-day migration when v2 ships |
| Stable error codes (§10) | Two implementations must agree on *why* they reject, not only *that* they reject |
