import { describe, expect, it } from "vitest";
import { bls12_381 } from "@noble/curves/bls12-381";

import { hashTypedData, hashTypedDataHex, TypedDataError, type HashTypedDataInput } from "../typed-data/hash.js";
import {
  BLS_SIGN_DST,
  TYPED_DATA_SIG_TAG,
  buildTypedDataSignedMessage,
  verifyBlsDigest,
  verifyTypedDataSignature,
} from "./sig.js";

/**
 * Deterministic BLS12-381 test key pair. Not derived from any wallet seed -
 * this module's tests generate and own their own keys.
 */
const TEST_SK = 424242424242424242424242424242n % bls12_381.fields.Fr.ORDER;
const TEST_PK_BYTES = bls12_381.G2.ProjectivePoint.BASE.multiply(TEST_SK).toRawBytes(true);
const TEST_PK_HEX = `0x${bytesToHex(TEST_PK_BYTES)}`;

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Sign `message` (raw bytes) with the standard Dusk BLS DST, as a wallet would. */
function signRaw(message: Uint8Array, skScalar: bigint): Uint8Array {
  const point = bls12_381.G1.hashToCurve(message, { DST: BLS_SIGN_DST });
  return point.multiply(skScalar).toRawBytes(true);
}

const TYPED_DATA_SIG_TAG_BYTES = new TextEncoder().encode(TYPED_DATA_SIG_TAG);

/** Build `SIG_TAG || digest` (spec 12.1) the same way the signer does. */
function taggedMessage(digest: Uint8Array): Uint8Array {
  const out = new Uint8Array(TYPED_DATA_SIG_TAG_BYTES.length + digest.length);
  out.set(TYPED_DATA_SIG_TAG_BYTES, 0);
  out.set(digest, TYPED_DATA_SIG_TAG_BYTES.length);
  return out;
}

const domain = { name: "Example", version: "1", chainId: "dusk:1" };
const domainTypes = {
  DuskTypedDataDomain: [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "string" },
    { name: "verifyingContract", type: "bytes32" },
  ],
};

function baseInput(overrides: Partial<HashTypedDataInput> = {}): HashTypedDataInput {
  return {
    domain,
    types: {
      ...domainTypes,
      Greeting: [{ name: "text", type: "string" }],
    },
    primaryType: "Greeting",
    message: { text: "hello" },
    origin: "https://app.example",
    ...overrides,
  };
}

function signTypedDataInput(input: HashTypedDataInput, skScalar: bigint): { signatureHex: string; digest: Uint8Array } {
  const { digest } = hashTypedData(input);
  const signature = signRaw(taggedMessage(digest), skScalar);
  return { signatureHex: `0x${bytesToHex(signature)}`, digest };
}

describe("./bls: TYPED_DATA_SIG_TAG (spec 12.1)", () => {
  it("pins the exact tag bytes and length", () => {
    expect(TYPED_DATA_SIG_TAG).toBe("DUSK_TYPED_DATA_SIG_V1\0");
    expect(TYPED_DATA_SIG_TAG_BYTES).toHaveLength(23);
    expect(Array.from(TYPED_DATA_SIG_TAG_BYTES)).toEqual([
      68, 85, 83, 75, 95, 84, 89, 80, 69, 68, 95, 68, 65, 84, 65, 95, 83, 73, 71, 95, 86, 49, 0,
    ]);
  });

  it("BLS_SIGN_DST matches the unchanged, standard Dusk V2 DST", () => {
    expect(BLS_SIGN_DST).toBe("BLS_SIG_BLS12381G1_XMD:SHA-256_DUSK_V2");
  });

  it("exposes no way to select a BLS scheme version", async () => {
    // On chain the version is height-dependent (V1 before Aegis, V2 after).
    // Typed data does not inherit that: it postdates the fork, so it has no
    // pre-V2 history to stay compatible with, and a selectable version would
    // put the insecure V1 path within reach (spec section 12.4).
    const blsModule = await import("./index.js");

    expect(Object.keys(blsModule).sort()).toEqual([
      "BLS_SIGN_DST",
      "TYPED_DATA_SIG_TAG",
      "buildTypedDataSignedMessage",
      "verifyBlsDigest",
      "verifyTypedDataSignature",
    ]);

    for (const name of Object.keys(blsModule)) {
      expect(name).not.toMatch(/insecure|v1\b|version|legacy/i);
    }
  });

  it("pins the V2 tag by value, not by reference to a library default", () => {
    // @noble/curves defaults G1 short signatures to the IETF ciphersuite
    // BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_. Signing and verifying under
    // that default is self-consistent and rejected by the chain, so every
    // round-trip test would still pass. Assert the value, not the variable.
    expect(BLS_SIGN_DST).not.toContain("SSWU_RO_NUL");
    expect(BLS_SIGN_DST).toContain("DUSK_V2");
  });
});

describe("./bls: buildTypedDataSignedMessage", () => {
  it("exports the existing tagged-message construction for wallet signers", () => {
    const digest = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(buildTypedDataSignedMessage(digest)).toEqual(taggedMessage(digest));
  });

  it.each([new Uint8Array(31), new Uint8Array(33), Array(32).fill(0), "0".repeat(32), null])(
    "rejects a non-32-byte Uint8Array input: %j",
    value => expect(() => buildTypedDataSignedMessage(value as Uint8Array)).toThrow(),
  );
});

/** Policy matching the fixtures in this file. */
const ACCEPTING_POLICY = { chainId: "dusk:1", origin: "https://app.example" } as const;
/** Deliberate opt-out, for the cases that are only about the cryptography. */
const ANY = { chainId: null, origin: null } as const;

describe("./bls: verifyTypedDataSignature", () => {
  it("requires a policy argument", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    // @ts-expect-error policy is required: a caller must not be able to
    // complete a verification without deciding chain and origin.
    expect(() => verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX)).toThrow();
  });

  it("reports the digest it verified, so a caller need not hash twice", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ACCEPTING_POLICY);

    expect(result.ok).toBe(true);
    expect(result.code).toBe("OK");
    expect(result.digestHex).toBe(hashTypedDataHex(input));
    expect(result.chainId).toBe("dusk:1");
    expect(result.origin).toBe("https://app.example");
  });

  it.each([
    ["chainId", "dusk:2", "E_CHAIN_MISMATCH"],
    ["origin", "https://other.example", "E_ORIGIN_MISMATCH"],
  ] as const)("checks the hashed %s even if a message getter changes the input", (field, expected, code) => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    const digestHex = hashTypedDataHex(input);
    Object.defineProperty(input.message, "text", {
      get() {
        if (field === "chainId") input.domain = { ...input.domain, chainId: expected };
        else input.origin = expected;
        return "hello";
      },
    });

    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, {
      ...ACCEPTING_POLICY, [field]: expected,
    });
    expect(field === "chainId" ? input.domain.chainId : input.origin).toBe(expected);
    expect(result).toEqual({ ...ACCEPTING_POLICY, digestHex, ok: false, code });
  });

  it("captures the expected policy before hashing can invoke a message getter", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    const policy = { chainId: "dusk:2", origin: "https://other.example" };
    Object.defineProperty(input.message, "text", {
      get() {
        Object.assign(policy, ACCEPTING_POLICY);
        return "hello";
      },
    });
    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, policy);
    expect(policy).toEqual(ACCEPTING_POLICY);
    expect(result.ok).toBe(false);
    expect(result.code).toBe("E_CHAIN_MISMATCH");
  });

  it("accepts stable accessors and non-enumerable domain fields", () => {
    const input = baseInput({ domain: { ...domain } });
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    Object.defineProperty(input.domain, "chainId", { enumerable: false });
    Object.defineProperty(input.message, "text", { get: () => "hello" });
    expect(Object.keys(input.domain)).not.toContain("chainId");
    expect(verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ACCEPTING_POLICY)).toMatchObject({
      ...ACCEPTING_POLICY, ok: true, code: "OK",
    });
  });

  it("REJECTS a cryptographically valid signature for another chain", () => {
    // Spec 12.3 step 4. The signature is genuine; the caller is verifying for
    // a chain the signer did not sign for.
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, {
      chainId: "dusk:2",
      origin: "https://app.example",
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe("E_CHAIN_MISMATCH");
    expect(result.chainId).toBe("dusk:1");
  });

  it("REJECTS a cryptographically valid signature from another origin", () => {
    // Spec 12.3 step 5.
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, {
      chainId: "dusk:1",
      origin: "https://other.example",
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe("E_ORIGIN_MISMATCH");
    expect(result.origin).toBe("https://app.example");
  });

  it("does not normalize the origin", () => {
    // A trailing slash is a different origin. Normalizing here would let a
    // verifier accept an origin the signer never displayed.
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const result = verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, {
      chainId: "dusk:1",
      origin: "https://app.example/",
    });

    expect(result.code).toBe("E_ORIGIN_MISMATCH");
  });

  it("accepts any chain or origin only when explicitly opted out with null", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    expect(verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ANY).ok).toBe(true);
    expect(
      verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, {
        chainId: null,
        origin: "https://app.example",
      }).ok
    ).toBe(true);
  });

  it("reports the signature failure before the policy failure", () => {
    // Spec 12.3 checks the signature first. A forged payload must not be
    // reported as a mere policy mismatch.
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    const tampered = baseInput({ origin: "https://evil.example" });

    const result = verifyTypedDataSignature(tampered, signatureHex, TEST_PK_HEX, {
      chainId: "dusk:2",
      origin: "https://app.example",
    });

    expect(result.code).toBe("E_SIG_INVALID");
  });

  it("verifies a known-good tagged signature (round trip)", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    expect(verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ACCEPTING_POLICY).ok).toBe(true);
  });

  // The security property this module exists to provide: a raw-digest signing
  // oracle must not be able to forge a typed-data signature.
  it("REJECTS a signature produced over the bare digest, not the tagged message", () => {
    const input = baseInput();
    const { digest } = hashTypedData(input);
    const bareSignature = signRaw(digest, TEST_SK);
    const bareSignatureHex = `0x${bytesToHex(bareSignature)}`;

    // Sanity: the bare-digest signature does verify under the bare-digest verifier.
    expect(verifyBlsDigest(`0x${bytesToHex(digest)}`, bareSignatureHex, TEST_PK_HEX)).toBe(true);

    // But it must not satisfy the typed-data verifier.
    expect(verifyTypedDataSignature(input, bareSignatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails when the message value is tampered with", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const tampered = baseInput({ message: { text: "goodbye" } });
    expect(verifyTypedDataSignature(tampered, signatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails when the domain is tampered with", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const tampered = baseInput({ domain: { ...domain, version: "2" } });
    expect(verifyTypedDataSignature(tampered, signatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails when the origin is tampered with", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const tampered = baseInput({ origin: "https://evil.example" });
    expect(verifyTypedDataSignature(tampered, signatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails when the signature is tampered with", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    // Flip a byte deep in the point encoding (not the leading flag bits) so
    // this stays a "wrong signature" case; flipping the flag byte instead
    // would produce a malformed point encoding, which is covered separately
    // below (verification returns `ok: false` either way, never throws,
    // for a correctly-sized but bad signature).
    const bytes = Uint8Array.from(Buffer.from(signatureHex.slice(2), "hex"));
    bytes[bytes.length - 1] ^= 0xff;
    const tamperedSignatureHex = `0x${bytesToHex(bytes)}`;

    expect(verifyTypedDataSignature(input, tamperedSignatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails (does not throw) when the signature bytes are correctly sized but not a valid point", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const bytes = Uint8Array.from(Buffer.from(signatureHex.slice(2), "hex"));
    bytes[0] ^= 0xff; // corrupts the compression/sign flag bits
    const invalidPointSignatureHex = `0x${bytesToHex(bytes)}`;

    expect(verifyTypedDataSignature(input, invalidPointSignatureHex, TEST_PK_HEX, ANY).ok).toBe(false);
  });

  it("fails when verified against the wrong public key", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);

    const otherSk = (TEST_SK + 1n) % bls12_381.fields.Fr.ORDER;
    const otherPkHex = `0x${bytesToHex(
      bls12_381.G2.ProjectivePoint.BASE.multiply(otherSk).toRawBytes(true)
    )}`;

    expect(verifyTypedDataSignature(input, signatureHex, otherPkHex, ANY).ok).toBe(false);
  });

  it("throws on an invalid typed-data payload (spec section 10)", () => {
    const input = baseInput({ primaryType: "DuskTypedDataDomain" });
    expect(() => verifyTypedDataSignature(input, `0x${"00".repeat(48)}`, TEST_PK_HEX, ANY)).toThrow();
  });

  it("reports coded structural refusal through the public verifier", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    expect(verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ACCEPTING_POLICY).ok).toBe(true);
    input.types.Greeting = [{ name: "text", type: `uint8${"[1]".repeat(100)}` }];
    try {
      verifyTypedDataSignature(input, signatureHex, TEST_PK_HEX, ACCEPTING_POLICY);
    } catch (error) {
      expect(error).toBeInstanceOf(TypedDataError);
      expect(error).toMatchObject({ code: "E_COMPLEXITY" });
      return;
    }
    throw new Error("Expected structural refusal");
  });

  it("throws on a malformed signatureHex", () => {
    const input = baseInput();
    expect(() => verifyTypedDataSignature(input, "not-hex", TEST_PK_HEX, ANY)).toThrow();
    expect(() => verifyTypedDataSignature(input, `0x${"00".repeat(47)}`, TEST_PK_HEX, ANY)).toThrow();
  });

  it("throws on a malformed publicKeyHex", () => {
    const input = baseInput();
    const { signatureHex } = signTypedDataInput(input, TEST_SK);
    expect(() => verifyTypedDataSignature(input, signatureHex, "not-hex", ANY)).toThrow();
    expect(() => verifyTypedDataSignature(input, signatureHex, `0x${"00".repeat(95)}`, ANY)).toThrow();
  });
});

describe("./bls: verifyBlsDigest (bare digest, NOT the typed-data verifier)", () => {
  it("verifies a signature produced over a bare 32-byte digest", () => {
    const digest = new Uint8Array(32).fill(0x77);
    const signature = signRaw(digest, TEST_SK);
    const digestHex = `0x${bytesToHex(digest)}`;
    const signatureHex = `0x${bytesToHex(signature)}`;

    expect(verifyBlsDigest(digestHex, signatureHex, TEST_PK_HEX)).toBe(true);
  });

  it("rejects when the digest differs", () => {
    const digest = new Uint8Array(32).fill(0x11);
    const other = new Uint8Array(32).fill(0x22);
    const signature = signRaw(digest, TEST_SK);

    expect(
      verifyBlsDigest(`0x${bytesToHex(other)}`, `0x${bytesToHex(signature)}`, TEST_PK_HEX)
    ).toBe(false);
  });

  it("throws on a non-32-byte digestHex", () => {
    const signature = signRaw(new Uint8Array(32), TEST_SK);
    expect(() =>
      verifyBlsDigest(`0x${"00".repeat(31)}`, `0x${bytesToHex(signature)}`, TEST_PK_HEX)
    ).toThrow();
  });
});
