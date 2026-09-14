/**
 * Dusk typed-data hash v1.
 *
 * Normative spec: docs/typed-data-v1.md, sections 4-11.
 *
 * encodeType(S) is encodeTypeLocal(S) followed by encodeTypeLocal(D) for every
 * struct D in deps(S) \ {S}, sorted by UTF-8 bytes of the type name. The
 * *primary* type's own local encoding always comes first (spec 6.1) - it is
 * NOT merged into the sorted list of dependencies.
 *
 * Encoded width is a function of the type alone (spec 4.1): `string` and
 * `bytes` both encode to a 32-byte sha256 digest of their content, so there is
 * no value-dependent size budget to enforce as part of digest validity (spec
 * 11). Signer policy remains separate (`checkPolicyLimits` is never called
 * from hashing). The reference encoder also bounds structural work with a
 * coded refusal above the interoperability floor; see spec 11.1.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes as concat } from "@noble/hashes/utils";

export type FieldDef = { name: string; type: string };

export type HashTypedDataInput = {
  domain: {
    name: string;
    version: string;
    chainId: string;
    verifyingContract?: string;
  };
  types: Record<string, FieldDef[]>;
  primaryType: string;
  message: Record<string, unknown>;
  origin: string;
};

/** Stable validation/resource error code, see docs/typed-data-v1.md sections 10-11. */
export type TypedDataErrorCode =
  | "E_PARAMS_SHAPE"
  | "E_PRIMARY_MISSING"
  | "E_PRIMARY_INVALID"
  | "E_DOMAIN_TYPE"
  | "E_DOMAIN_VALUE"
  | "E_TYPE_UNKNOWN"
  | "E_TYPE_INVALID"
  | "E_TYPE_CYCLE"
  | "E_FIELD_DUP"
  | "E_FIELD_RESERVED"
  | "E_FIELD_DEF"
  | "E_FIELD_MISSING"
  | "E_FIELD_EXTRA"
  | "E_VALUE_TYPE"
  | "E_ARRAY_LENGTH"
  | "E_UINT_RANGE"
  | "E_UINT_FORMAT"
  | "E_HEX_FORMAT"
  | "E_BYTES32_LENGTH"
  | "E_ORIGIN_TYPE"
  | "E_UTF8"
  | "E_POLICY_LIMIT"
  | "E_COMPLEXITY";

/** Error raised by the typed-data hash/validation/policy paths; carries a stable `.code`. */
export class TypedDataError extends Error {
  code: TypedDataErrorCode;

  constructor(code: TypedDataErrorCode, message: string) {
    super(message);
    this.name = "TypedDataError";
    this.code = code;
  }
}

const PREAMBLE = utf8("DUSK_TYPED_DATA_V1\0");
const ORIGIN_TAG = utf8("DUSK_ORIGIN_BIND_V1\0");
const ATOMIC = new Set([
  "string",
  "bytes",
  "bytes32",
  "uint64",
  "uint32",
  "uint8",
  "bool",
]);
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
// n must be `[1-9][0-9]*` - this already rejects `T[0]`, `T[01]`, and `T[]`
// (no digits at all does not match) by construction.
const ARRAY_FIXED = /^(.+)\[([1-9][0-9]*)\]$/;
const DOMAIN_TYPE = "DuskTypedDataDomain";
const ZERO32 = new Uint8Array(32);
const RESERVED_FIELD_NAMES = new Set(["__proto__", "constructor", "prototype"]);

// Signer-side resource floor, spec section 11. Not part of digest validity;
// see `checkPolicyLimits`.
const POLICY_LIMITS = {
  maxStructTypes: 32,
  maxFieldsPerStruct: 64,
  maxNestingDepth: 8,
  maxArrayElements: 256,
  maxStringBytes: 65536,
  maxJsonUtf8Bytes: 262144,
};

// Reference-implementation structural guards, not protocol validity or signer
// policy. All otherwise-valid JSON inputs within the spec 11 floor fit these.
const ENCODER_LIMITS = {
  maxDepth: 64,
  maxStructs: 128,
  maxFields: 8192,
  maxTypeChars: 1048576,
  maxValueVisits: 262144,
};

type ValueBudget = { visits: number };

function visitValue(budget: ValueBudget): void {
  // ponytail: visit count only; byte-work limits need a separate floor-preserving budget.
  if (++budget.visits > ENCODER_LIMITS.maxValueVisits) {
    fail("E_COMPLEXITY", `typed-data value visits exceed ${ENCODER_LIMITS.maxValueVisits}`);
  }
}

function fail(code: TypedDataErrorCode, message: string): never {
  throw new TypedDataError(code, message);
}

function checkDepth(depth: number): void {
  if (depth > ENCODER_LIMITS.maxDepth) {
    fail("E_COMPLEXITY", `typed-data traversal depth exceeds ${ENCODER_LIMITS.maxDepth}`);
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

export function validateTypedDataParams(params: unknown): asserts params is HashTypedDataInput {
  if (!isPlainObject(params)) {
    fail("E_PARAMS_SHAPE", "params must be an object");
  }
  if (!isPlainObject(params.types)) {
    fail("E_PARAMS_SHAPE", "types must be an object");
  }
  if (!isPlainObject(params.domain)) {
    fail("E_PARAMS_SHAPE", "domain must be an object");
  }
  if (!isPlainObject(params.message)) {
    fail("E_PARAMS_SHAPE", "message must be an object");
  }

  validatePrimaryType(params.primaryType, params.types as Record<string, FieldDef[]>);
  requireDomainType(params.types as Record<string, FieldDef[]>);
  domainMessage(params.domain as HashTypedDataInput["domain"]);

  if (typeof params.origin !== "string") {
    fail("E_ORIGIN_TYPE", "origin must be a string");
  }
}

/**
 * Signer-side resource limits, spec section 11. These are a FLOOR: verifiers
 * MUST accept any otherwise-valid payload within them, and signers SHOULD
 * reject payloads above them as local policy. They MUST NOT influence the
 * digest, so this is a separate function `hashTypedData` never calls.
 */
export function checkPolicyLimits(input: HashTypedDataInput): void {
  validateTypedDataParams(input);
  const types = input.types;

  const structTypes = new Set([
    ...collectStructDeps(DOMAIN_TYPE, types),
    ...collectStructDeps(input.primaryType, types),
  ]);
  if (structTypes.size > POLICY_LIMITS.maxStructTypes) {
    fail(
      "E_POLICY_LIMIT",
      `distinct struct types ${structTypes.size} exceeds floor ${POLICY_LIMITS.maxStructTypes}`
    );
  }
  for (const name of structTypes) {
    const fields = types[name]!;
    if (fields.length > POLICY_LIMITS.maxFieldsPerStruct) {
      fail(
        "E_POLICY_LIMIT",
        `${name} has ${fields.length} fields, exceeds floor ${POLICY_LIMITS.maxFieldsPerStruct}`
      );
    }
  }

  const budget = { visits: 0 };
  walkValueForPolicy(DOMAIN_TYPE, domainMessage(input.domain), types, budget, 1);
  walkValueForPolicy(input.primaryType, input.message, types, budget, 1);

  // Compact JSON UTF-8 bytes, including hex text and unused metadata (spec 11).
  // This is not the sum of decoded field bytes or a peak-memory bound.
  const totalBytes = utf8(JSON.stringify(input)).length;
  if (totalBytes > POLICY_LIMITS.maxJsonUtf8Bytes) {
    fail(
      "E_POLICY_LIMIT",
      `compact JSON input ${totalBytes} bytes exceeds floor ${POLICY_LIMITS.maxJsonUtf8Bytes}`
    );
  }
}

function walkValueForPolicy(
  typeExpr: string,
  value: unknown,
  types: Record<string, FieldDef[]>,
  budget: ValueBudget,
  depth: number
): void {
  visitValue(budget);
  if (depth > POLICY_LIMITS.maxNestingDepth) {
    fail("E_POLICY_LIMIT", `nesting depth exceeds floor ${POLICY_LIMITS.maxNestingDepth}`);
  }
  const t = classifyType(typeExpr);
  if (t.kind === "array") {
    if (!Array.isArray(value)) {
      return;
    }
    const length = value.length;
    if (length > POLICY_LIMITS.maxArrayElements) {
      fail(
        "E_POLICY_LIMIT",
        `array length ${length} exceeds floor ${POLICY_LIMITS.maxArrayElements}`
      );
    }
    for (let i = 0; i < length; i++) {
      walkValueForPolicy(t.elem, value[i], types, budget, depth + 1);
    }
    return;
  }
  if (t.kind === "atomic") {
    if ((t.name === "string" || t.name === "bytes") && typeof value === "string") {
      const byteLen = t.name === "string" ? utf8(value).length : hexByteLength(value);
      if (byteLen > POLICY_LIMITS.maxStringBytes) {
        fail(
          "E_POLICY_LIMIT",
          `${t.name} value ${byteLen} bytes exceeds floor ${POLICY_LIMITS.maxStringBytes}`
        );
      }
    }
    return;
  }
  if (!isPlainObject(value)) {
    return;
  }
  const fields = types[t.name] ?? [];
  for (let i = 0, n = fields.length; i < n; i++) {
    const f = fields[i]!;
    if (Object.hasOwn(value, f.name)) {
      walkValueForPolicy(f.type, value[f.name], types, budget, depth + 1);
    }
  }
}

function hexByteLength(value: string): number {
  const h = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  return Math.floor(h.length / 2);
}

export function hashTypedData(input: HashTypedDataInput): { digest: Uint8Array } {
  const { digest } = hashTypedDataWithContext(input);
  return { digest };
}

export function hashTypedDataHex(input: HashTypedDataInput): `0x${string}` {
  return toHex(hashTypedData(input).digest);
}

/** Intermediates from spec section 9, used for the golden vector format (spec section 15). */
export type HashTypedDataDebug = {
  typeHashes: Record<string, `0x${string}`>;
  domainSeparator: `0x${string}`;
  originBind: `0x${string}`;
  structHash: `0x${string}`;
  digestHex: `0x${string}`;
};

/**
 * Like `hashTypedData`, but also returns the intermediates from spec section
 * 9 (per-struct typeHash, domainSeparator, originBind, structHash of the
 * primary type) so a mismatch against another implementation localizes to a
 * single stage.
 */
export function hashTypedDataDebug(input: HashTypedDataInput): HashTypedDataDebug {
  validateTypedDataParams(input);
  const types = input.types;
  const domainValues = domainMessage(input.domain);
  const hashes = new Map<string, Uint8Array>();
  const budget = { visits: 0 };

  // Compute the digest stages in the same order as `hashTypedDataWithContext`, so that an
  // input violating several rules at once reports the same error code from
  // both entry points (spec section 10, "Reporting order").
  const domainSeparator = structHash(DOMAIN_TYPE, domainValues, types, hashes, budget);
  const originBind = originBindHash(input.origin);
  const structHashPrimary = structHash(input.primaryType, input.message, types, hashes, budget);

  const reachable = new Set([
    ...collectStructDeps(DOMAIN_TYPE, types),
    ...collectStructDeps(input.primaryType, types),
  ]);
  const typeHashes: Record<string, `0x${string}`> = Object.create(null);
  for (const name of reachable) {
    typeHashes[name] = toHex(typeHash(name, types, hashes));
  }
  const digest = sha256(concat(PREAMBLE, domainSeparator, originBind, structHashPrimary));

  return {
    typeHashes,
    domainSeparator: toHex(domainSeparator),
    originBind: toHex(originBind),
    structHash: toHex(structHashPrimary),
    digestHex: toHex(digest),
  };
}

/** @internal Returns the context used in the digest, not a later read of the caller's object. */
export function hashTypedDataWithContext(input: HashTypedDataInput) {
  validateTypedDataParams(input);
  const types = input.types;
  const domainValues = domainMessage(input.domain);
  const hashes = new Map<string, Uint8Array>();
  const budget = { visits: 0 };
  const domainSeparator = structHash(DOMAIN_TYPE, domainValues, types, hashes, budget);
  const origin = input.origin;
  const originBind = originBindHash(origin);
  const structHashPrimary = structHash(input.primaryType, input.message, types, hashes, budget);
  const digest = sha256(concat(PREAMBLE, domainSeparator, originBind, structHashPrimary));
  return { digest, chainId: domainValues.chainId, origin };
}

function originBindHash(origin: string): Uint8Array {
  if (typeof origin !== "string") {
    fail("E_ORIGIN_TYPE", "origin must be a string");
  }
  return sha256(concat(ORIGIN_TAG, sha256(utf8(origin))));
}

function domainMessage(domain: HashTypedDataInput["domain"]): Required<HashTypedDataInput["domain"]> {
  if (!isPlainObject(domain)) {
    fail("E_PARAMS_SHAPE", "domain must be an object");
  }
  if (
    typeof domain.name !== "string" ||
    typeof domain.version !== "string" ||
    typeof domain.chainId !== "string"
  ) {
    fail("E_DOMAIN_VALUE", "domain.name, domain.version, domain.chainId required strings");
  }
  let verifyingContract: string;
  if (domain.verifyingContract === undefined) {
    verifyingContract = toHex(ZERO32);
  } else if (typeof domain.verifyingContract !== "string") {
    fail("E_DOMAIN_VALUE", "domain.verifyingContract must be a hex string");
  } else {
    verifyingContract = domain.verifyingContract;
  }
  return {
    name: domain.name,
    version: domain.version,
    chainId: domain.chainId,
    verifyingContract,
  };
}

function requireDomainType(types: Record<string, FieldDef[]>): void {
  if (!Object.hasOwn(types, DOMAIN_TYPE)) {
    fail("E_DOMAIN_TYPE", "types must include DuskTypedDataDomain");
  }
  const fields = types[DOMAIN_TYPE];
  const want: Array<[string, string]> = [
    ["name", "string"],
    ["version", "string"],
    ["chainId", "string"],
    ["verifyingContract", "bytes32"],
  ];
  if (!Array.isArray(fields) || fields.length !== want.length) {
    fail("E_DOMAIN_TYPE", "DuskTypedDataDomain field list mismatch");
  }
  for (let i = 0; i < want.length; i++) {
    const f = fields[i];
    const [wantName, wantType] = want[i]!;
    if (!f || f.name !== wantName || f.type !== wantType) {
      fail("E_DOMAIN_TYPE", "DuskTypedDataDomain fields must match canonical order");
    }
  }
}

function validatePrimaryType(primaryType: unknown, types: Record<string, FieldDef[]>): asserts primaryType is string {
  if (typeof primaryType !== "string") {
    fail("E_PRIMARY_MISSING", "primaryType is required");
  }
  if (primaryType === DOMAIN_TYPE) {
    fail("E_PRIMARY_INVALID", "primaryType must not be DuskTypedDataDomain");
  }
  if (ATOMIC.has(primaryType)) {
    fail("E_PRIMARY_INVALID", "primaryType must not be an atomic type");
  }
  if (ARRAY_FIXED.test(primaryType)) {
    fail("E_PRIMARY_INVALID", "primaryType must not be an array type");
  }
  if (!IDENT.test(primaryType)) {
    fail("E_PRIMARY_INVALID", "primaryType must be a valid identifier");
  }
  if (!Object.hasOwn(types, primaryType)) {
    fail("E_PRIMARY_MISSING", "primaryType missing from types");
  }
}

type TypeClassification =
  | { kind: "array"; elem: string; n: number }
  | { kind: "atomic"; name: string }
  | { kind: "struct"; name: string };

/**
 * Classify one type expression: atomic, fixed array, or struct reference.
 * This is the single place that enforces spec section 4's syntax rules, so
 * every caller (dependency-graph walk, value encoding) agrees on E_TYPE_INVALID.
 */
function classifyType(typeExpr: string): TypeClassification {
  if (typeof typeExpr !== "string") {
    fail("E_TYPE_INVALID", "type expression must be a string");
  }
  if (typeExpr.length > ENCODER_LIMITS.maxTypeChars) {
    fail("E_COMPLEXITY", `type expression exceeds ${ENCODER_LIMITS.maxTypeChars} characters`);
  }
  if (/\s/.test(typeExpr)) {
    fail("E_TYPE_INVALID", `whitespace in type expression: ${typeExpr}`);
  }
  const m = ARRAY_FIXED.exec(typeExpr);
  if (m) {
    return { kind: "array", elem: m[1]!, n: Number(m[2]) };
  }
  if (typeExpr.includes("[") || typeExpr.includes("]")) {
    // T[], T[0], T[01], or any other malformed array expression.
    fail("E_TYPE_INVALID", `malformed array type: ${typeExpr}`);
  }
  if (ATOMIC.has(typeExpr)) {
    return { kind: "atomic", name: typeExpr };
  }
  if (!IDENT.test(typeExpr)) {
    fail("E_TYPE_INVALID", `invalid type name: ${typeExpr}`);
  }
  return { kind: "struct", name: typeExpr };
}

function structFields(typeName: string, types: Record<string, FieldDef[]>): FieldDef[] {
  if (!Object.hasOwn(types, typeName)) {
    fail("E_TYPE_UNKNOWN", `unknown type: ${typeName}`);
  }
  const fields = types[typeName];
  if (!Array.isArray(fields)) {
    fail("E_FIELD_DEF", `${typeName}: field list must be an array`);
  }
  return fields;
}

function checkFieldDefs(typeName: string, fields: FieldDef[]): number {
  const names = new Set<string>();
  let chars = typeName.length + 2 + Math.max(0, fields.length - 1);
  for (let i = 0, n = fields.length; i < n; i++) {
    const f = fields[i];
    if (!f || typeof f !== "object" || typeof f.name !== "string" || typeof f.type !== "string") {
      fail("E_FIELD_DEF", `${typeName}: bad field definition`);
    }
    chars += f.type.length + 1 + f.name.length;
    if (chars > ENCODER_LIMITS.maxTypeChars) {
      fail("E_COMPLEXITY", `type encoding exceeds ${ENCODER_LIMITS.maxTypeChars} characters`);
    }
    if (!IDENT.test(f.name)) {
      fail("E_FIELD_DEF", `${typeName}: bad field definition`);
    }
    if (RESERVED_FIELD_NAMES.has(f.name)) {
      fail("E_FIELD_RESERVED", `${typeName}.${f.name}: reserved field name`);
    }
    if (names.has(f.name)) {
      fail("E_FIELD_DUP", `${typeName}: duplicate field ${f.name}`);
    }
    names.add(f.name);
  }
  return chars;
}

/** Collect one dependency closure, bounding work before descending or encoding. */
function collectStructDeps(typeExpr: string, types: Record<string, FieldDef[]>): Set<string> {
  const visited = new Set<string>();
  const stack = new Set<string>();
  let fieldCount = 0;
  let chars = 0;

  function walk(expr: string, depth: number): void {
    checkDepth(depth);
    const t = classifyType(expr);
    if (t.kind === "array") {
      walk(t.elem, depth + 1);
      return;
    }
    if (t.kind === "atomic") return;
    const name = t.name;
    if (stack.has(name)) fail("E_TYPE_CYCLE", `type cycle involving ${name}`);
    if (visited.has(name)) return;
    if (visited.size + stack.size >= ENCODER_LIMITS.maxStructs) {
      fail("E_COMPLEXITY", `dependency closure exceeds ${ENCODER_LIMITS.maxStructs} struct types`);
    }
    const fields = structFields(name, types);
    fieldCount += fields.length;
    if (fieldCount > ENCODER_LIMITS.maxFields) {
      fail("E_COMPLEXITY", `dependency closure exceeds ${ENCODER_LIMITS.maxFields} fields`);
    }
    chars += checkFieldDefs(name, fields);
    if (chars > ENCODER_LIMITS.maxTypeChars) {
      fail("E_COMPLEXITY", `type encoding exceeds ${ENCODER_LIMITS.maxTypeChars} characters`);
    }
    stack.add(name);
    for (let i = 0, n = fields.length; i < n; i++) {
      walk(fields[i]!.type, depth + 1);
    }
    stack.delete(name);
    visited.add(name);
  }

  walk(typeExpr, 1);
  return visited;
}

function encodeTypeLocal(name: string, fields: FieldDef[]): string {
  const parts: string[] = [];
  for (let i = 0, n = fields.length; i < n; i++) {
    const f = fields[i]!;
    parts.push(`${f.type} ${f.name}`);
  }
  return `${name}(${parts.join(",")})`;
}

/**
 * encodeType(S), spec 6.1: S's own local encoding first, then its
 * dependencies (deps(S) \ {S}) sorted ascending by UTF-8 bytes of the type
 * name.
 */
function encodeType(typeName: string, types: Record<string, FieldDef[]>): string {
  const visited = collectStructDeps(typeName, types);
  const deps: string[] = [];
  for (const name of visited) {
    if (name !== typeName) {
      deps.push(name);
    }
  }
  // ASCII identifiers have the same native and UTF-8 ordering.
  deps.sort();
  const parts = [encodeTypeLocal(typeName, types[typeName]!)];
  for (const d of deps) {
    parts.push(encodeTypeLocal(d, types[d]!));
  }
  return parts.join("");
}

function typeHash(typeName: string, types: Record<string, FieldDef[]>, hashes: Map<string, Uint8Array>): Uint8Array {
  let hash = hashes.get(typeName);
  if (!hash) {
    hash = sha256(utf8(encodeType(typeName, types)));
    hashes.set(typeName, hash);
  }
  return hash;
}

function structHash(
  typeName: string,
  values: unknown,
  types: Record<string, FieldDef[]>,
  hashes: Map<string, Uint8Array>,
  budget: ValueBudget,
  depth = 1
): Uint8Array {
  visitValue(budget);
  const hash = sha256.create().update(typeHash(typeName, types, hashes));
  const fields = types[typeName]!;
  if (!isPlainObject(values)) {
    fail("E_VALUE_TYPE", `${typeName}: expected object value`);
  }
  const seen = new Set<string>();
  for (let i = 0, n = fields.length; i < n; i++) {
    const f = fields[i]!;
    if (!Object.hasOwn(values, f.name)) {
      fail("E_FIELD_MISSING", `missing field ${typeName}.${f.name}`);
    }
    seen.add(f.name);
    for (const part of encodeValue(f.type, values[f.name], types, hashes, budget, depth + 1)) hash.update(part);
  }
  // Include non-enumerable and symbol keys in the own-property check (spec 6.3).
  for (const k of Reflect.ownKeys(values)) {
    if (typeof k !== "string" || !seen.has(k)) {
      fail("E_FIELD_EXTRA", `unexpected field ${typeName}.${String(k)}`);
    }
  }
  return hash.digest();
}

/** Arrays stream their indexed concatenated encoding without a JS argument list. */
function* encodeValue(
  typeExpr: string, value: unknown, types: Record<string, FieldDef[]>,
  hashes: Map<string, Uint8Array>, budget: ValueBudget, depth: number
): Generator<Uint8Array> {
  checkDepth(depth);
  const t = classifyType(typeExpr);
  // Struct visits are charged in structHash, including the two root structs.
  if (t.kind !== "struct") visitValue(budget);
  if (t.kind === "array") {
    if (!Array.isArray(value)) {
      fail("E_VALUE_TYPE", `${typeExpr}: expected array`);
    }
    if (value.length !== t.n) {
      fail("E_ARRAY_LENGTH", `${typeExpr}: expected length ${t.n}, got ${value.length}`);
    }
    for (let i = 0; i < t.n; i++) {
      yield* encodeValue(t.elem, value[i], types, hashes, budget, depth + 1);
    }
    return;
  }
  if (t.kind === "atomic") {
    yield encAtomic(t.name, value);
    return;
  }
  if (!isPlainObject(value)) {
    fail("E_VALUE_TYPE", `${t.name}: expected object`);
  }
  yield structHash(t.name, value, types, hashes, budget, depth);
}

function encAtomic(typeName: string, value: unknown): Uint8Array {
  switch (typeName) {
    case "string": {
      if (typeof value !== "string") {
        fail("E_VALUE_TYPE", "string field requires JSON string");
      }
      return sha256(utf8(value));
    }
    case "bytes": {
      const raw = decodeHex(value, "bytes");
      return sha256(raw);
    }
    case "bytes32": {
      const raw = decodeHex(value, "bytes32");
      if (raw.length !== 32) {
        fail("E_BYTES32_LENGTH", "bytes32 requires exactly 32 bytes (no padding)");
      }
      return raw;
    }
    case "uint64":
      return be(parseUint(value, 64), 8);
    case "uint32":
      return be(parseUint(value, 32), 4);
    case "uint8":
      return be(parseUint(value, 8), 1);
    case "bool": {
      if (typeof value !== "boolean") {
        fail("E_VALUE_TYPE", "bool field requires JSON boolean");
      }
      return new Uint8Array([value ? 1 : 0]);
    }
    default:
      // classifyType() only returns ATOMIC names here, so this is unreachable.
      fail("E_TYPE_INVALID", `unsupported atomic ${typeName}`);
  }
}

function parseUint(value: unknown, bits: number): bigint {
  let n: bigint;
  if (typeof value === "number") {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
      fail("E_UINT_RANGE", "uint JSON number must be a safe integer");
    }
    n = BigInt(value);
  } else if (typeof value === "string") {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) {
      fail("E_UINT_FORMAT", "uint string must be decimal with no leading zeros");
    }
    n = BigInt(value);
  } else {
    fail("E_VALUE_TYPE", "uint requires a number or a decimal string");
  }
  if (n < 0n) {
    fail("E_UINT_RANGE", "uint cannot be negative");
  }
  const max = (1n << BigInt(bits)) - 1n;
  if (n > max) {
    fail("E_UINT_RANGE", `uint${bits} overflow`);
  }
  return n;
}

function be(n: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  let x = n;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function decodeHex(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string") {
    fail("E_VALUE_TYPE", `${label} requires 0x-hex string`);
  }
  let h = value;
  if (h.startsWith("0x") || h.startsWith("0X")) {
    h = h.slice(2);
  }
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
    fail("E_HEX_FORMAT", `${label}: invalid hex encoding`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function utf8(s: string): Uint8Array {
  // Unicode mode matches lone surrogates, not valid surrogate pairs.
  if (/[\uD800-\uDFFF]/u.test(s)) {
    fail("E_UTF8", "UTF-8 input contains an unpaired surrogate");
  }
  return new TextEncoder().encode(s);
}

function toHex(bytes: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(bytes)}`;
}
