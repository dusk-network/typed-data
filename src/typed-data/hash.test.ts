import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";

import {
  checkPolicyLimits,
  hashTypedData,
  hashTypedDataDebug,
  hashTypedDataHex,
  validateTypedDataParams,
  type TypedDataErrorCode,
  type HashTypedDataInput,
  TypedDataError,
} from "./hash.js";

const VECTOR_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "vectors",
  "typed-data-v1"
);

function loadVector(name: string): any {
  return JSON.parse(readFileSync(path.join(VECTOR_DIR, name), "utf8"));
}

/** Assert `fn` throws a `TypedDataError` with the given stable spec-10 error code. */
function expectCode(fn: () => unknown, code: TypedDataErrorCode): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(TypedDataError);
  expect((caught as TypedDataError).code).toBe(code);
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
const origin = "https://app.example";

describe("typed-data hash v1", () => {
  it.each(readdirSync(VECTOR_DIR).filter(name => name.endsWith(".json")))(
    "matches golden digest for %s",
    (name) => {
      const vector = loadVector(name);
      expect(hashTypedDataHex(vector.input)).toBe(vector.digestHex);
    }
  );

  it.each(readdirSync(path.join(VECTOR_DIR, "reject")).filter(name => name.endsWith(".json")))(
    "rejects frozen vector %s",
    name => {
      const vector = loadVector(`reject/${name}`);
      for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
        expectCode(() => hash(vector.input), vector.error);
      }
    }
  );

  it("rejects missing primaryType with E_PRIMARY_MISSING", () => {
    const vector = loadVector("sign_in_basic.json");
    expectCode(
      () => validateTypedDataParams({ ...vector.input, primaryType: undefined }),
      "E_PRIMARY_MISSING"
    );
  });

  it("rejects a types map missing DuskTypedDataDomain with E_DOMAIN_TYPE", () => {
    const vector = loadVector("sign_in_basic.json");
    const types = { ...vector.input.types };
    delete types.DuskTypedDataDomain;
    expectCode(
      () => validateTypedDataParams({ ...vector.input, types }),
      "E_DOMAIN_TYPE"
    );
  });
});

describe("string/bytes encoding (spec 5.1)", () => {
  it("hashes large array elements without sharing a policy budget", () => {
    expect(hashTypedDataHex({
      domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [{ name: "parts", type: "string[2]" }] },
      message: { parts: ["y".repeat(400_000), "y".repeat(400_000)] },
    })).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("does not apply any value-dependent size budget (spec 11 removes it from validity)", () => {
    const big = "x".repeat(2_000_000);
    expect(() =>
      hashTypedDataHex({
        domain,
        types: { ...domainTypes, Big: [{ name: "blob", type: "string" }] },
        primaryType: "Big",
        message: { blob: big },
        origin,
      })
    ).not.toThrow();
  });
});

describe("fixed-array indexed encoding (spec 5.3)", () => {
  it.each([["replacement", [2]], ["empty", []], ["extra", [1, 2]]] as const)(
    "ignores a custom %s iterator", (_name, yielded) => {
      const items = Object.defineProperty([1], Symbol.iterator, {
        value: function* () { yield* yielded; },
      });
      const input = {
        domain, origin, primaryType: "A",
        types: { ...domainTypes, A: [{ name: "items", type: "uint8[1]" }] },
        message: { items },
      };
      const plain = { ...input, message: { items: [1] } };
      expect(items[0]).toBe(1);
      expect(JSON.stringify(items)).toBe("[1]");
      expect(hashTypedData(input)).toEqual(hashTypedData(plain));
      expect(hashTypedDataHex(input)).toBe(hashTypedDataHex(plain));
      expect(hashTypedDataDebug(input).structHash).toBe(`0x${bytesToHex(sha256(concatBytes(
        sha256(new TextEncoder().encode("A(uint8[1] items)")), new Uint8Array([1]),
      )))}`);
    },
  );

  it("does not shorten the declared traversal when an indexed getter shrinks the array", () => {
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      const items = [1, 2];
      Object.defineProperty(items, "0", { get() { items.length = 1; return 1; } });
      expectCode(() => hash({
        domain, origin, primaryType: "A",
        types: { ...domainTypes, A: [{ name: "items", type: "uint8[2]" }] },
        message: { items },
      }), "E_VALUE_TYPE");
    }
  });
});

describe("indexed field definitions (spec 6)", () => {
  function fieldInput(): HashTypedDataInput {
    return {
      domain, origin, primaryType: "Msg",
      types: { ...structuredClone(domainTypes), Msg: [
        { name: "a", type: "uint8" }, { name: "b", type: "uint8" },
      ] },
      message: { a: 1, b: 2 },
    };
  }

  it("requires every indexed field even when the iterator omits one", () => {
    const input = fieldInput();
    delete input.message.b;
    Object.defineProperty(input.types.Msg, Symbol.iterator, {
      value: function* () { yield this[0]; },
    });
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(input), "E_FIELD_MISSING");
    }
  });

  it("encodes indexed declaration order, not iterator order", () => {
    const input = fieldInput();
    const plain = structuredClone(input);
    Object.defineProperty(input.types.Msg, Symbol.iterator, {
      value: function* () { yield this[1]; yield this[0]; },
    });
    const expected = sha256(concatBytes(
      sha256(new TextEncoder().encode("Msg(uint8 a,uint8 b)")), new Uint8Array([1, 2]),
    ));
    expect(hashTypedDataDebug(input).structHash).toBe(`0x${bytesToHex(expected)}`);
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expect(hash(input)).toEqual(hash(plain));
    }
  });

  it.each([
    ["duplicate", "a", "uint8", "E_FIELD_DUP"],
    ["reserved", "__proto__", "uint8", "E_FIELD_RESERVED"],
    ["malformed", "x,b", "uint8", "E_FIELD_DEF"],
    ["unknown", "b", "Missing", "E_TYPE_UNKNOWN"],
    ["array syntax", "b", "uint8[]", "E_TYPE_INVALID"],
    ["cycle", "b", "Msg", "E_TYPE_CYCLE"],
  ] as const)("cannot skip %s field validation", (_label, name, type, code) => {
    const input = fieldInput();
    input.types.Msg![1] = { name, type };
    input.message = { a: 1 };
    Object.defineProperty(input.types.Msg, Symbol.iterator, {
      value: function* () { yield this[0]; },
    });
    for (const check of [hashTypedData, hashTypedDataHex, hashTypedDataDebug, checkPolicyLimits]) {
      expectCode(() => check(input), code);
    }
  });

  it.each(["DuskTypedDataDomain", "Msg", "Child"])(
    "does not read iterator or map hooks on %s field lists", owner => {
      for (const hook of [Symbol.iterator, "map"]) {
        const input = fieldInput();
        input.types.Msg![1]!.type = "Child";
        input.types.Child = [{ name: "c", type: "uint8" }];
        input.message.b = { c: 2 };
        const plain = structuredClone(input);
        Object.defineProperty(input.types[owner], hook, {
          get() { throw new Error(`unexpected field-list hook: ${String(hook)}`); },
        });
        expect(hashTypedDataDebug(input).typeHashes.Msg).toBe(`0x${bytesToHex(sha256(
          new TextEncoder().encode("Msg(uint8 a,Child b)Child(uint8 c)"),
        ))}`);
        for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
          expect(hash(input)).toEqual(hash(plain));
        }
        expect(() => checkPolicyLimits(input)).not.toThrow();
      }
    },
  );
});

describe("uint64 JSON", () => {
  it("rejects unsafe JSON number for uint64 with E_UINT_RANGE", () => {
    expectCode(
      () =>
        hashTypedDataHex({
          domain,
          types: { ...domainTypes, U: [{ name: "n", type: "uint64" }] },
          primaryType: "U",
          message: { n: 9007199254740993 },
          origin,
        }),
      "E_UINT_RANGE"
    );
  });

  it("rejects decimal string overflow for uint64 with E_UINT_RANGE", () => {
    expectCode(
      () =>
        hashTypedDataHex({
          domain,
          types: { ...domainTypes, U: [{ name: "n", type: "uint64" }] },
          primaryType: "U",
          message: { n: "18446744073709551616" },
          origin,
        }),
      "E_UINT_RANGE"
    );
  });
});

describe("validation error codes (spec section 10)", () => {
  it.each([
    ["domain", { ...domain, verifyingContract: "0x11" }, origin, "E_BYTES32_LENGTH"],
    ["origin", domain, "\ud800", "E_UTF8"],
  ] as const)("reports the %s error before a malformed message type from every hash entrypoint", (_stage, domain, origin, code) => {
    const input = {
      domain, origin, primaryType: "S", message: {},
      types: { ...domainTypes, S: [{ name: "value", type: "Missing[]" }] },
    };
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(input), code);
    }
  });

  it("rejects an empty types map before hashing", () => {
    const vector = loadVector("sign_in_basic.json");
    expectCode(() => validateTypedDataParams({ ...vector.input, types: {} }), "E_PRIMARY_MISSING");
  });

  it.each([
    ["non-enumerable string", "hidden", false],
    ["enumerable symbol", Symbol("hidden"), true],
    ["non-enumerable symbol", Symbol("hidden"), false],
  ] as const)("E_FIELD_EXTRA: rejects an undeclared %s property", (_label, key, enumerable) => {
    const vector = loadVector("sign_in_basic.json");
    Object.defineProperty(vector.input.message, key, { value: "extra", enumerable });
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(vector.input), "E_FIELD_EXTRA");
    }
  });

  it("accepts a declared non-enumerable own field", () => {
    const vector = loadVector("sign_in_basic.json");
    const plain = loadVector("sign_in_basic.json");
    Object.defineProperty(vector.input.message, "address", { enumerable: false });
    expect(hashTypedDataHex(vector.input)).toBe(vector.digestHex);
    for (const hash of [hashTypedData, hashTypedDataDebug]) {
      expect(hash(vector.input)).toEqual(hash(plain.input));
    }
  });

  it("rejects an origin accessor that stops returning a string", () => {
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      const vector = loadVector("sign_in_basic.json");
      let reads = 0;
      Object.defineProperty(vector.input, "origin", {
        get: () => reads++ === 0 ? origin : 123,
      });
      expectCode(() => hash(vector.input), "E_ORIGIN_TYPE");
    }
  });

  it("E_PRIMARY_INVALID: primaryType is DuskTypedDataDomain", () => {
    expectCode(
      () =>
        hashTypedData({
          domain,
          types: { ...domainTypes, S: [{ name: "text", type: "string" }] },
          primaryType: "DuskTypedDataDomain",
          message: domain,
          origin,
        }),
      "E_PRIMARY_INVALID"
    );
  });

  it("E_TYPE_INVALID: array size has a leading zero (T[01])", () => {
    expectCode(
      () =>
        hashTypedData({
          domain,
          types: { ...domainTypes, S: [{ name: "items", type: "uint8[01]" }] },
          primaryType: "S",
          message: { items: [1] },
          origin,
        }),
      "E_TYPE_INVALID"
    );
  });

  it("E_TYPE_INVALID: zero-length array (T[0])", () => {
    expectCode(
      () =>
        hashTypedData({
          domain,
          types: { ...domainTypes, S: [{ name: "items", type: "uint8[0]" }] },
          primaryType: "S",
          message: { items: [] },
          origin,
        }),
      "E_TYPE_INVALID"
    );
  });

  it("E_TYPE_CYCLE: mutually recursive struct types", () => {
    expectCode(
      () =>
        hashTypedData({
          domain,
          types: {
            ...domainTypes,
            A: [{ name: "b", type: "B" }],
            B: [{ name: "a", type: "A" }],
          },
          primaryType: "A",
          message: { b: { a: {} } },
          origin,
        }),
      "E_TYPE_CYCLE"
    );
  });

  it("E_FIELD_MISSING: field is present only via the prototype chain, not as an own property", () => {
    const vector = loadVector("sign_in_basic.json");
    const message = Object.assign(Object.create({ address: "via-prototype" }), {
      statement: "Sign in to Example",
    });
    expectCode(() => hashTypedData({ ...vector.input, message }), "E_FIELD_MISSING");
  });
});

describe("checkPolicyLimits (spec section 11)", () => {
  const smallInput = {
    domain,
    types: { ...domainTypes, S: [{ name: "text", type: "string" }] },
    primaryType: "S",
    message: { text: "hi" },
    origin,
  };

  it("accepts a payload within the floor", () => {
    expect(() => checkPolicyLimits(smallInput)).not.toThrow();
  });

  it.each([65536, 65537])("measures %i indexed string bytes, not array iterator values", length => {
    const text = "x".repeat(length);
    const items = Object.defineProperty([text], Symbol.iterator, {
      // The iterator deliberately describes the opposite policy outcome.
      value: function* () { if (length === 65536) yield "x".repeat(65537); },
    });
    const input = {
      ...smallInput, types: { ...domainTypes, S: [{ name: "items", type: "string[1]" }] },
      message: { items },
    };
    expect(Buffer.byteLength(JSON.stringify(input))).toBeLessThan(262144);
    expect(hashTypedDataHex(input)).toBe(hashTypedDataHex({ ...input, message: { items: [text] } }));
    if (length === 65536) expect(() => checkPolicyLimits(input)).not.toThrow();
    else expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
  });

  it("measures every indexed struct field even when its iterator skips a large string", () => {
    const fields = Object.defineProperty([{ name: "text", type: "string" }], Symbol.iterator, {
      value: function* () {},
    });
    const input = {
      ...smallInput, types: { ...domainTypes, S: fields }, message: { text: "x".repeat(65537) },
    };
    expect(Buffer.byteLength(JSON.stringify(input))).toBeLessThan(262144);
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
  });

  it("bounds the actual array length before reading elements", () => {
    const items = Array(257).fill("ok");
    Object.defineProperty(items, "0", { get() { throw new Error("element read before refusal"); } });
    expectCode(() => checkPolicyLimits({
      ...smallInput, types: { ...domainTypes, S: [{ name: "items", type: "string[257]" }] },
      message: { items },
    }), "E_POLICY_LIMIT");
  });

  it("does not use an unvalidated declared length as a policy loop bound", () => {
    const input = {
      ...smallInput, types: { ...domainTypes, S: [{ name: "items", type: "uint8[9999999999999999]" }] },
      message: { items: new Proxy([], {
        get(array, key, receiver) {
          if (key === "0") throw new Error("policy traversed an unvalidated declared length");
          return Reflect.get(array, key, receiver);
        },
      }) },
    };
    // Policy is not full value validation; hashing still rejects the length mismatch.
    expect(() => checkPolicyLimits(input)).not.toThrow();
    expectCode(() => hashTypedDataHex(input), "E_ARRAY_LENGTH");
  });

  it("counts compact JSON UTF-8, including escaping and unused metadata, with an inclusive limit", () => {
    const input = { ...smallInput, metadata: "\u0000é😀\\" };
    input.metadata += "x".repeat(262144 - Buffer.byteLength(JSON.stringify(input)));
    expect(Buffer.byteLength(JSON.stringify(input))).toBe(262144);
    expect(() => checkPolicyLimits(input)).not.toThrow();
    const escapedWire = JSON.stringify(input).replace("é", "\\u00e9");
    expect(Buffer.byteLength(escapedWire)).toBe(262148);
    expect(() => checkPolicyLimits(JSON.parse(escapedWire))).not.toThrow();
    const digest = hashTypedDataHex(input);
    input.metadata += "\n";
    expect(Buffer.byteLength(JSON.stringify(input))).toBe(262146);
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
    expect(() => checkPolicyLimits(input)).toThrow("compact JSON input 262146 bytes exceeds floor 262144");
    expect(hashTypedDataHex(input)).toBe(digest);
  });

  it("counts hex text in the total, but decoded bytes for each bytes value", () => {
    const input = {
      domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [{ name: "parts", type: "bytes[2]" }] },
      message: { parts: Array(2).fill(`0x${"ab".repeat(65536)}`) },
    };
    expect(Buffer.byteLength(JSON.stringify(input))).toBeGreaterThan(262144);
    expect(hashTypedDataHex(input)).toMatch(/^0x[0-9a-f]{64}$/);
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
    expect(() => checkPolicyLimits(input)).toThrow("compact JSON input");
    input.message.parts = Array(2).fill(`0x${"ab".repeat(32768)}`);
    expect(() => checkPolicyLimits(input)).not.toThrow();
  });

  it("counts traversal depth from root 1 through atomic leaves", () => {
    for (const arrays of [6, 7]) {
      let value: unknown = 1;
      for (let i = 0; i < arrays; i++) value = [value];
      const input = {
        domain, origin, primaryType: "S",
        types: { ...domainTypes, S: [{ name: "value", type: `uint8${"[1]".repeat(arrays)}` }] },
        message: { value },
      };
      expect(hashTypedDataHex(input)).toMatch(/^0x[0-9a-f]{64}$/);
      if (arrays === 6) expect(() => checkPolicyLimits(input)).not.toThrow();
      else expect(() => checkPolicyLimits(input)).toThrow("nesting depth exceeds floor 8");
    }
  });

  it("does not count unreachable schema entries as traversed struct types", () => {
    const input = {
      ...smallInput,
      types: {
        ...smallInput.types,
        ...Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`Unused${i}`, []])),
      },
    };
    expect(() => checkPolicyLimits(input)).not.toThrow();
    expect(hashTypedDataHex(input)).toBe(hashTypedDataHex(smallInput));
  });

  it("hashTypedData does not enforce policy limits - only checkPolicyLimits does", () => {
    const fields = Array.from({ length: 65 }, (_, i) => ({
      name: `f${i}`,
      type: "uint8",
    }));
    const message = Object.fromEntries(fields.map((f) => [f.name, 1]));
    const bigInput = {
      domain,
      types: { ...domainTypes, Big: fields },
      primaryType: "Big",
      message,
      origin,
    };

    expect(() => hashTypedDataHex(bigInput)).not.toThrow();
    expectCode(() => checkPolicyLimits(bigInput), "E_POLICY_LIMIT");
  });

  it("enforces the struct-count floor without also exceeding the depth floor", () => {
    for (const count of [30, 31]) {
      const names = Array.from({ length: count }, (_, i) => `S${i}`);
      const input = {
        domain, origin, primaryType: "Root",
        types: {
          ...domainTypes,
          Root: names.map(name => ({ name, type: name })),
          ...Object.fromEntries(names.map(name => [name, [{ name: "value", type: "uint8" }]])),
        },
        message: Object.fromEntries(names.map(name => [name, { value: 1 }])),
      };
      // Domain + Root + children: 32 structs pass, 33 fail; depth stays at 3.
      if (count === 30) expect(() => checkPolicyLimits(input)).not.toThrow();
      else expect(() => checkPolicyLimits(input)).toThrow("distinct struct types 33 exceeds floor 32");
    }
  });

  it("rejects more than 256 elements in a fixed array with E_POLICY_LIMIT", () => {
    const input = {
      domain,
      types: { ...domainTypes, Arr: [{ name: "items", type: "uint8[257]" }] },
      primaryType: "Arr",
      message: { items: Array.from({ length: 257 }, () => 1) },
      origin,
    };
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
  });
});

describe("encoder structural guards", () => {
  function chain(count: number) {
    const types: Record<string, Array<{ name: string; type: string }>> = { ...domainTypes };
    let message: Record<string, unknown> = {};
    for (let i = count - 1; i >= 0; i--) {
      types[`L${i}`] = i === count - 1 ? [] : [{ name: "next", type: `L${i + 1}` }];
      if (i < count - 1) message = { next: message };
    }
    return { domain, origin, types, primaryType: "L0", message };
  }

  it("accepts depth 64 and refuses depth 65 consistently", () => {
    const input = chain(64);
    expect(hashTypedDataDebug(input).digestHex).toBe(hashTypedDataHex(input));
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(chain(65)), "E_COMPLEXITY");
    }
  });

  it("refuses a deep schema before reading its remaining definitions, including through policy", () => {
    const input = chain(5000);
    input.message = {};
    validateTypedDataParams(input); // Initial shape checking is not a full graph walk.
    let reached = false;
    Object.defineProperty(input.types, "L64", { get() { reached = true; throw new Error("walk continued"); } });
    for (const check of [hashTypedData, hashTypedDataHex, hashTypedDataDebug, checkPolicyLimits]) {
      expectCode(() => check(input), "E_COMPLEXITY");
    }
    expect(reached).toBe(false);
  });

  it("bounds nested array expressions as well as struct chains", () => {
    const input = { domain, origin, primaryType: "S", message: { value: 1 },
      types: { ...domainTypes, S: [{ name: "value", type: `uint8${"[1]".repeat(5000)}` }] } };
    for (const check of [hashTypedData, hashTypedDataDebug, checkPolicyLimits]) {
      expectCode(() => check(input), "E_COMPLEXITY");
    }
  });

  it("bounds each dependency closure at 128 distinct structs, independently of unused types", () => {
    for (const count of [127, 128]) {
      const names = Array.from({ length: count }, (_, i) => `T${i}`);
      const input = { domain, origin, primaryType: "S",
        types: { ...domainTypes, S: names.map(name => ({ name, type: name })),
          ...Object.fromEntries(names.map(name => [name, []])), Ignored: [{ name: "bad", type: "NoSuchType" }] },
        message: Object.fromEntries(names.map(name => [name, {}])) };
      for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
        if (count === 127) expect(() => hash(input)).not.toThrow();
        else expectCode(() => hash(input), "E_COMPLEXITY");
      }
    }
  });

  it("bounds the total fields across a dependency closure at 8192", () => {
    for (const count of [8191, 8192]) {
      const fields = Array.from({ length: count }, (_, i) => ({ name: `f${i}`, type: "uint8" }));
      const input = { domain, origin, primaryType: "S",
        types: { ...domainTypes, S: [{ name: "child", type: "Child" }], Child: fields },
        message: { child: Object.fromEntries(fields.map(field => [field.name, 1])) } };
      if (count === 8191) expect(hashTypedDataDebug(input).digestHex).toBe(hashTypedDataHex(input));
      else expectCode(() => hashTypedDataHex(input), "E_COMPLEXITY");
    }
  });

  it("checks value depth even when a shared dependency was visited on a shorter path", () => {
    const input = chain(63);
    const next = input.message;
    input.types.Root = [{ name: "first", type: "L0" }, { name: "second", type: "More" }];
    input.types.More = [{ name: "next", type: "L0" }];
    input.primaryType = "Root";
    input.message = { first: next, second: { next } };
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(input), "E_COMPLEXITY");
    }
  });

  it("bounds type-encoding text at 1048576 characters without bounding string values", () => {
    for (const length of [1048576 - 9, 1048576 - 8]) {
      const name = "x".repeat(length); // S(uint8 <name>) adds nine ASCII characters.
      const input = { domain, origin, primaryType: "S",
        types: { ...domainTypes, S: [{ name, type: "uint8" }] }, message: { [name]: 1 } };
      if (length === 1048576 - 9) expect(() => hashTypedDataHex(input)).not.toThrow();
      else expectCode(() => hashTypedDataHex(input), "E_COMPLEXITY");
    }
  });

  it("streams wide arrays without a native argument-spread limit", () => {
    const count = 140000;
    const input = { domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [{ name: "values", type: `uint8[${count}]` }] },
      message: { values: Array(count).fill(1) } };
    const typeHash = sha256(new TextEncoder().encode(`S(uint8[${count}] values)`));
    const expected = `0x${bytesToHex(sha256(concatBytes(typeHash, new Uint8Array(count).fill(1))))}`;
    expect(hashTypedDataDebug(input).structHash).toBe(expected);
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
  });

  it("reuses a type hash for repeated values only within the current call", () => {
    const fields = [{ name: "value", type: "uint8" }];
    let reads = 0;
    const input = { domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [{ name: "values", type: "Leaf[512]" }], get Leaf() { reads++; return fields; } },
      message: { values: Array(512).fill({ value: 1 }) as Record<string, number>[] } };
    const first = hashTypedDataHex(input);
    expect(reads).toBeLessThan(1024);
    fields[0]!.name = "other";
    input.message.values = Array(512).fill({ other: 1 });
    expect(hashTypedDataHex(input)).not.toBe(first);
  });
});

describe("encoder total-value budget", () => {
  function arrayInput(type: string, values: unknown): HashTypedDataInput {
    return { domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [{ name: "values", type }] }, message: { values } };
  }

  function arrayStructHash(type: string, bytes: Uint8Array): string {
    return `0x${bytesToHex(sha256(concatBytes(
      sha256(new TextEncoder().encode(`S(${type} values)`)), bytes,
    )))}`;
  }

  it("counts both roots, arrays and atomics with an inclusive per-call limit", () => {
    // Domain root + four fields + primary root + array = seven visits.
    const count = 262144 - 7;
    const input = arrayInput(`uint8[${count}]`, Array(count).fill(1));
    const debug = hashTypedDataDebug(input);
    expect(debug.structHash).toBe(arrayStructHash(`uint8[${count}]`, new Uint8Array(count).fill(1)));
    expect(hashTypedDataHex(input)).toBe(debug.digestHex);
    expect(`0x${bytesToHex(hashTypedData(input).digest)}`).toBe(debug.digestHex);
    const over = arrayInput(`uint8[${count + 1}]`, Array(count + 1).fill(1));
    for (const hash of [hashTypedData, hashTypedDataHex, hashTypedDataDebug]) {
      expectCode(() => hash(over), "E_COMPLEXITY");
    }
    // Refusal must not poison a later call's budget.
    const small = loadVector("sign_in_basic.json");
    expect(hashTypedDataHex(small.input)).toBe(small.digestHex);
  });

  it("charges every shared array container as well as its atomic leaves", () => {
    const count = (262144 - 7) / 3;
    // Each outer element visits two shared array containers and one atomic.
    const input = arrayInput(`uint8[1][1][${count}]`, Array(count).fill([[1]]));
    expect(hashTypedDataDebug(input).structHash).toBe(arrayStructHash(
      `uint8[1][1][${count}]`, new Uint8Array(count).fill(1),
    ));
    expectCode(() => hashTypedDataHex(arrayInput(
      `uint8[1][1][${count + 1}]`, Array(count + 1).fill([[1]]),
    )), "E_COMPLEXITY");
  });

  it("charges shared empty structs exactly once per path, even with cached type hashes", () => {
    const count = 262144 - 7;
    const input = arrayInput(`Leaf[${count}]`, Array(count).fill({}));
    input.types.Leaf = [];
    const leafHash = sha256(sha256(new TextEncoder().encode("Leaf()")));
    const expected = sha256.create().update(sha256(new TextEncoder().encode(`S(Leaf[${count}] values)Leaf()`)));
    for (let i = 0; i < count; i++) expected.update(leafHash);
    expect(hashTypedDataDebug(input).structHash).toBe(`0x${bytesToHex(expected.digest())}`);
    const over = arrayInput(`Leaf[${count + 1}]`, Array(count + 1).fill({}));
    over.types.Leaf = [];
    expectCode(() => hashTypedDataHex(over), "E_COMPLEXITY");
  }, 15000);

  it.each(["arrays", "structs"])("bounds cloned shared %s before policy JSON serialization", kind => {
    let values: unknown = kind === "arrays" ? 0 : {};
    for (let i = 0; i < 3; i++) values = Array(64).fill(values);
    const input = structuredClone(arrayInput(`${kind === "arrays" ? "uint8" : "Leaf"}[64][64][64]`, values));
    if (kind === "structs") input.types.Leaf = [];
    const outer = input.message.values as unknown[];
    expect(outer[0]).toBe(outer[1]); // Structured clone preserves aliases.
    validateTypedDataParams(input); // Shape checking is still not a value walk.
    Object.defineProperty(input, "toJSON", {
      value() { throw new Error("serialization reached before typed-value refusal"); },
    });
    // All individual array lengths, depths and schema dimensions fit the signer
    // floor; the expanded value tree does not fit its compact-JSON byte limit.
    for (const check of [hashTypedData, hashTypedDataHex, hashTypedDataDebug, checkPolicyLimits]) {
      expectCode(() => check(input), "E_COMPLEXITY");
    }
  }, 15000);

  it("shares the same inclusive budget across both policy roots", () => {
    // 6 root/domain visits + 261125 + 772 + 241 = 262144.
    const input = arrayInput("uint8[255][255][4]", Array(4).fill(Array(255).fill(Array(255).fill(0))));
    input.types.S!.push({ name: "b", type: "uint8[256][3]" }, { name: "c", type: "uint8[240]" });
    input.message.b = Array(3).fill(Array(256).fill(0));
    input.message.c = Array(240).fill(0);
    // The visit walk fits; the expanded JSON does not fit signer policy.
    expectCode(() => checkPolicyLimits(input), "E_POLICY_LIMIT");
    expect(() => checkPolicyLimits(input)).toThrow("compact JSON input");
    input.types.S!.push({ name: "extra", type: "bool" });
    input.message.extra = false;
    expectCode(() => checkPolicyLimits(input), "E_COMPLEXITY");
  });

  it("preserves dense floor-sized JSON inputs and their alias-preserving equivalents", () => {
    const type = "uint8[256][254][2]";
    const input = { ...arrayInput(type, Array(2).fill(Array(254).fill(Array(256).fill(0)))), metadata: "" };
    const length = Buffer.byteLength(JSON.stringify(input));
    expect(length).toBeLessThanOrEqual(262144);
    input.metadata = "x".repeat(262144 - length);
    const wire = JSON.stringify(input);
    expect(Buffer.byteLength(wire)).toBe(262144);
    const parsed = JSON.parse(wire);
    for (const value of [input, parsed]) expect(() => checkPolicyLimits(value)).not.toThrow();
    const debug = hashTypedDataDebug(parsed);
    expect(debug.structHash).toBe(arrayStructHash(type, new Uint8Array(256 * 254 * 2)));
    expect(hashTypedDataHex(input)).toBe(debug.digestHex);
  });
});

describe("encoding boundaries", () => {
  it.each([
    ["a,uint8 b", "c"],
    ["a", "b,uint8 c"],
    ["", "c"],
    ["9a", "c"],
    ["a\n", "c"],
  ])("rejects non-identifier field names %j / %j", (first, second) => {
    expectCode(() => hashTypedData({
      domain, origin, primaryType: "S",
      types: { ...domainTypes, S: [first, second].map(name => ({ name, type: "uint8" })) },
      message: { [first]: 1, [second]: 2 },
    }), "E_FIELD_DEF");
  });

  const textInput = {
    domain, origin, primaryType: "S",
    types: { ...domainTypes, S: [{ name: "text", type: "string" }] },
    message: { text: "" },
  };

  it.each([
    ["high surrogate", { message: { text: "\ud800" } }],
    ["low surrogate", { message: { text: "\udfff" } }],
    ["domain", { domain: { ...domain, name: "\ud800" } }],
    ["origin", { origin: "\udfff" }],
  ])("rejects ill-formed Unicode in %s", (_label, overrides) => {
    expectCode(() => hashTypedData({ ...textInput, ...overrides }), "E_UTF8");
  });

  it("preserves valid Unicode without normalization", () => {
    const hashText = (text: string) => hashTypedDataHex({ ...textInput, message: { text } });
    expect(hashText("\ufffd")).toBe("0x7067f98b33dd88ed2bef97cea668e7d438ec0013e85ad89505845162fa1d720c");
    expect(() => hashText("\ud83d\ude00")).not.toThrow();
    expect(hashText("\u00e9")).not.toBe(hashText("e\u0301"));
  });

  it("returns an own typeHash for the valid __proto__ struct name", () => {
    const input = {
      domain, origin, primaryType: "__proto__",
      types: { ...domainTypes, ["__proto__"]: [] }, message: {},
    };
    const debug = hashTypedDataDebug(input);
    expect(Object.hasOwn(debug.typeHashes, "__proto__")).toBe(true);
    expect(debug.typeHashes["__proto__"]).toMatch(/^0x[0-9a-f]{64}$/);
    expect(debug.digestHex).toBe(hashTypedDataHex(input));
  });
});
