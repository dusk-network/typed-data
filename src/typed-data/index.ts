/**
 * Dusk typed-data v1 hashing.
 *
 * The root entrypoint contains no wallet, provider or BLS-curve integration.
 * Import `@dusk/typed-data/bls` separately for tagged signature verification.
 *
 * @example
 * ```ts
 * import { hashTypedDataHex } from "@dusk/typed-data";
 * ```
 *
 * @module
 */

export type { FieldDef, HashTypedDataInput, TypedDataErrorCode, HashTypedDataDebug } from "./hash.js";
export {
  TypedDataError,
  hashTypedData,
  hashTypedDataHex,
  hashTypedDataDebug,
  validateTypedDataParams,
  checkPolicyLimits,
} from "./hash.js";
